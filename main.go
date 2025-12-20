package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bougou/go-ipmi"
)

// --- 嵌入静态资源 ---

//go:embed static
var staticFiles embed.FS

// --- 配置与常量 ---

const (
	defaultPollInterval = 30 * time.Second
	defaultWebBind      = "0.0.0.0"
	defaultWebPort      = "8080"
	defaultFanCurve     = "1-14:10,15-19:15,20-24:20,25-29:25,30-34:30"

	// 默认传感器配置
	defaultCurveSensorID = "04h" // 默认用进气温度跑曲线
	defaultSafeSensorID  = "0eh" // 默认用 CPU 温度做安全接管
	defaultSafeThreshold = 60    // 默认 60 度触发自动

	defaultIPMIPort = 623
)

// Config 存储配置
type Config struct {
	Host         string
	User         string
	Password     string
	Port         int
	PollInterval time.Duration
	WebBind      string
	WebPort      string
	FanCurve     []FanRule
	ScanMode     bool

	// 传感器配置
	CurveSensorID int // 用于计算曲线的传感器 (如进气)
	SafeSensorID  int // 用于判断安全托管的传感器 (如 CPU)
	PowerSensorID int // 仅用于显示的功耗传感器

	// 阈值
	SafeThreshold int // 安全传感器超过此值 -> 自动模式

	// 校准参数
	Scale  float64
	Offset int
}

// FanRule 风扇规则
type FanRule struct {
	MinTemp int `json:"min_temp"`
	MaxTemp int `json:"max_temp"`
	Speed   int `json:"speed"`
}

// AppState 运行时状态
type AppState struct {
	mu            sync.RWMutex
	CurveTemp     int       `json:"curve_temp"`    // 曲线参照温度
	SafeTemp      int       `json:"safe_temp"`     // 安全参照温度
	PowerUsage    int       `json:"power_usage"`   // 功耗
	FanSpeedPct   int       `json:"fan_speed_pct"` // 设定转速
	Mode          string    `json:"mode"`
	ConfigSummary string    `json:"config_summary"` // 用于前端显示当前策略
	LastUpdated   time.Time `json:"last_updated"`
	LastError     string    `json:"last_error,omitempty"`
	CurrentCurve  []FanRule `json:"current_curve"`
}

// --- 全局状态 ---

var (
	state = &AppState{
		Mode: "初始化中",
	}
)

// --- 主程序入口 ---

func main() {
	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	state.mu.Lock()
	state.CurrentCurve = cfg.FanCurve
	state.ConfigSummary = fmt.Sprintf("安全托管: 传感器[0x%02x] > %d°C", cfg.SafeSensorID, cfg.SafeThreshold)
	state.mu.Unlock()

	if cfg.ScanMode {
		runScanMode(cfg)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go startWebServer(cfg.WebBind, cfg.WebPort)

	log.Printf("启动 iDRAC 风扇控制 (目标: %s:%d)", cfg.Host, cfg.Port)
	log.Printf("策略: 传感器[0x%02x]控制曲线, 传感器[0x%02x] > %d°C 时触发自动",
		cfg.CurveSensorID, cfg.SafeSensorID, cfg.SafeThreshold)

	runPersistentControlLoop(ctx, cfg)
}

// --- 配置逻辑 ---

func parseConfig() (*Config, error) {
	cfg := &Config{}

	host := flag.String("ip", os.Getenv("IDRAC_IP"), "iDRAC IP 地址")
	user := flag.String("user", os.Getenv("IDRAC_USER"), "iDRAC 用户名")
	pass := flag.String("password", os.Getenv("IDRAC_PASSWORD"), "iDRAC 密码")

	scan := flag.Bool("scan", false, "扫描模式")

	// 传感器参数
	curveSensorStr := flag.String("sensor", getEnvOrDefault("SENSOR_CURVE", defaultCurveSensorID), "控制曲线的传感器 ID (默认进气 04h)")
	safeSensorStr := flag.String("sensor-safe", getEnvOrDefault("SENSOR_SAFE", defaultSafeSensorID), "安全托管传感器 ID (默认 CPU 0eh)")
	pwrSensorStr := flag.String("sensor-power", "", "功耗传感器 ID (仅显示)")

	// 阈值参数
	safeThreshold := flag.Int("threshold", defaultSafeThreshold, "安全传感器触发自动模式的阈值")

	bind := flag.String("bind", getEnvOrDefault("WEB_BIND", defaultWebBind), "Web 监听地址")
	port := flag.String("port", getEnvOrDefault("WEB_PORT", defaultWebPort), "Web 端口")
	intervalStr := flag.String("interval", getEnvOrDefault("POLL_INTERVAL", "30s"), "轮询间隔")
	curveStr := flag.String("curve", getEnvOrDefault("FAN_CURVE", defaultFanCurve), "风扇曲线")

	// 校准参数
	scaleStr := flag.Float64("scale", 1.0, "温度比例系数")
	offsetStr := flag.Int("offset", -128, "温度偏移量 (默认 -128)")

	flag.Parse()

	// 环境变量覆盖
	if v := os.Getenv("TEMP_SCALE"); v != "" {
		if s, err := strconv.ParseFloat(v, 64); err == nil {
			*scaleStr = s
		}
	}
	if v := os.Getenv("TEMP_OFFSET"); v != "" {
		if o, err := strconv.Atoi(v); err == nil {
			*offsetStr = o
		}
	}

	if *host == "" || *user == "" || *pass == "" {
		return nil, fmt.Errorf("缺少凭据 (ip, user, password)")
	}

	cfg.Host = *host
	cfg.User = *user
	cfg.Password = *pass
	cfg.Port = defaultIPMIPort
	cfg.WebBind = *bind
	cfg.WebPort = *port
	cfg.SafeThreshold = *safeThreshold
	cfg.Scale = *scaleStr
	cfg.Offset = *offsetStr
	cfg.ScanMode = *scan

	var err error
	if cfg.CurveSensorID, err = parseHexID(*curveSensorStr); err != nil {
		return nil, fmt.Errorf("曲线传感器 ID 无效: %v", err)
	}
	if cfg.SafeSensorID, err = parseHexID(*safeSensorStr); err != nil {
		return nil, fmt.Errorf("安全传感器 ID 无效: %v", err)
	}
	cfg.PowerSensorID, _ = parseHexID(*pwrSensorStr)

	if cfg.PollInterval, err = time.ParseDuration(*intervalStr); err != nil {
		return nil, fmt.Errorf("时间间隔无效: %v", err)
	}
	if cfg.FanCurve, err = parseFanCurve(*curveStr); err != nil {
		return nil, fmt.Errorf("风扇曲线无效: %v", err)
	}

	return cfg, nil
}

func parseHexID(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, "h")
	s = strings.TrimPrefix(s, "0x")
	val, err := strconv.ParseInt(s, 16, 64)
	return int(val), err
}

func parseFanCurve(raw string) ([]FanRule, error) {
	var rules []FanRule
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		segment := strings.Split(part, ":")
		if len(segment) != 2 {
			continue
		}
		rangeParts := strings.Split(segment[0], "-")
		if len(rangeParts) != 2 {
			continue
		}
		min, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
		max, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
		speed, _ := strconv.Atoi(strings.TrimSpace(segment[1]))
		rules = append(rules, FanRule{MinTemp: min, MaxTemp: max, Speed: speed})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].MinTemp < rules[j].MinTemp })
	return rules, nil
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- 扫描模式 ---

func runScanMode(cfg *Config) {
	client, err := ipmi.NewClient(cfg.Host, cfg.Port, cfg.User, cfg.Password)
	if err != nil {
		log.Fatalf("客户端错误: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		log.Fatalf("连接错误: %v", err)
	}
	defer client.Close(context.Background())

	log.Println("=== 传感器扫描 (Offset: -128) ===")
	fmt.Printf("%-10s | %-10s | %s\n", "ID", "Raw", "Temp(C)")
	fmt.Println(strings.Repeat("-", 40))

	for i := 0; i < 256; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		reading, err := client.GetSensorReading(ctx, uint8(i))
		cancel()
		if err == nil {
			raw := int(reading.Reading)
			fmt.Printf("0x%02x       | %-10d | %d\n", i, raw, raw-128)
		}
	}
}

// --- 控制循环 ---

func runPersistentControlLoop(ctx context.Context, cfg *Config) {
	var client *ipmi.Client
	var err error
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	closeClient := func() {
		if client != nil {
			_ = client.Close(context.Background())
			client = nil
		}
	}

	defer func() {
		log.Println(">>> 程序退出，恢复 BIOS 自动控制...")
		if client == nil {
			// 尝试临时重连
			tmp, e := ipmi.NewClient(cfg.Host, cfg.Port, cfg.User, cfg.Password)
			if e == nil && tmp.Connect(context.Background()) == nil {
				client = tmp
			}
		}
		if client != nil {
			_ = setIPMIDynamicControl(context.Background(), client, true)
			closeClient()
		}
	}()

	for {
		if client == nil {
			client, err = connectIPMI(ctx, cfg)
			if err != nil {
				handleError(fmt.Errorf("连接重试: %v", err))
				goto WAIT
			}
		}

		if err := processCycle(ctx, client, cfg); err != nil {
			handleError(err)
			log.Println("通信异常，重置连接...")
			closeClient()
		}

	WAIT:
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			return
		case <-ticker.C:
			continue
		}
	}
}

func connectIPMI(ctx context.Context, cfg *Config) (*ipmi.Client, error) {
	client, err := ipmi.NewClient(cfg.Host, cfg.Port, cfg.User, cfg.Password)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

func processCycle(ctx context.Context, client *ipmi.Client, cfg *Config) error {
	opCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	metrics, err := collectAllMetrics(opCtx, client, cfg)
	if err != nil {
		return err
	}

	updateStateMetrics(metrics)

	return executeFanControl(opCtx, client, cfg, metrics)
}

type MetricResult struct {
	CurveTemp int // 用于曲线的温度
	SafeTemp  int // 用于安全的温度
	Power     int
}

func collectAllMetrics(ctx context.Context, client *ipmi.Client, cfg *Config) (MetricResult, error) {
	res := MetricResult{}

	// 1. 读取曲线传感器 (如进气)
	t1, _, err := getIPMISensorValue(ctx, client, cfg.CurveSensorID, cfg.Scale, cfg.Offset)
	if err != nil {
		return res, fmt.Errorf("读取曲线传感器(0x%x)失败: %w", cfg.CurveSensorID, err)
	}
	res.CurveTemp = t1

	// 2. 读取安全传感器 (如 CPU)
	// 如果 ID 相同，直接复用，减少 IPMI 请求
	if cfg.SafeSensorID == cfg.CurveSensorID {
		res.SafeTemp = t1
	} else {
		t2, _, err := getIPMISensorValue(ctx, client, cfg.SafeSensorID, cfg.Scale, cfg.Offset)
		if err != nil {
			// 安全传感器读取失败是严重错误吗？暂且记录但不中断循环，防止程序崩溃
			log.Printf("读取安全传感器(0x%x)失败: %v", cfg.SafeSensorID, err)
			res.SafeTemp = -999 // 标记无效
		} else {
			res.SafeTemp = t2
		}
	}

	// 3. 读取功耗 (可选)
	if cfg.PowerSensorID > 0 {
		p, _, err := getIPMISensorValue(ctx, client, cfg.PowerSensorID, 1.0, 0)
		if err == nil {
			res.Power = p
		}
	}

	return res, nil
}

func executeFanControl(ctx context.Context, client *ipmi.Client, cfg *Config, m MetricResult) error {
	// 简单的异常数据过滤
	if m.CurveTemp > 100 && cfg.Offset == 0 {
		log.Printf("⚠️ 曲线温度读数异常 (%d°C)，跳过控制", m.CurveTemp)
		return nil
	}

	// 核心逻辑：安全传感器是否超标
	forceAuto := false
	reason := ""

	if m.SafeTemp != -999 && m.SafeTemp >= cfg.SafeThreshold {
		forceAuto = true
		reason = fmt.Sprintf("安全传感器(0x%x) %d°C >= %d°C", cfg.SafeSensorID, m.SafeTemp, cfg.SafeThreshold)
	}

	if forceAuto {
		// 切换到动态 (BIOS) 控制
		if state.Mode != "动态" {
			log.Printf("触发阈值 [%s]. 切换 BIOS 托管", reason)
			if err := setIPMIDynamicControl(ctx, client, true); err != nil {
				return err
			}
			updateStateMode("动态", 0)
		}
	} else {
		// 切换到手动控制
		speed := calculateFanSpeed(m.CurveTemp, cfg.FanCurve)

		// 每次都强制发送“禁用动态控制”，防止被外部重置
		if err := setIPMIDynamicControl(ctx, client, false); err != nil {
			return err
		}
		if err := setIPMIFanSpeed(ctx, client, speed); err != nil {
			return err
		}

		// 降低日志频率
		if state.Mode != "手动" || abs(state.FanSpeedPct-speed) >= 5 {
			log.Printf("CurveTemp: %d°C | SafeTemp: %d°C | Fan: %d%%", m.CurveTemp, m.SafeTemp, speed)
		}
		updateStateMode("手动", speed)
	}
	return nil
}

func calculateFanSpeed(temp int, rules []FanRule) int {
	for _, r := range rules {
		if temp >= r.MinTemp && temp <= r.MaxTemp {
			return r.Speed
		}
	}
	if len(rules) > 0 {
		return rules[0].Speed
	}
	return 20
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func getIPMISensorValue(ctx context.Context, client *ipmi.Client, id int, scale float64, offset int) (int, int, error) {
	r, err := client.GetSensorReading(ctx, uint8(id))
	if err != nil {
		return 0, 0, err
	}
	raw := int(r.Reading)
	val := int(float64(raw)*scale) + offset
	return val, raw, nil
}

// --- IPMI Commands ---

type DellOEMRequest struct {
	NetFn uint8
	Cmd   uint8
	Data  []byte
}

func (r *DellOEMRequest) Command() ipmi.Command {
	return ipmi.Command{NetFn: ipmi.NetFn(r.NetFn), ID: r.Cmd}
}
func (r *DellOEMRequest) Pack() []byte { return r.Data }

type DellOEMResponse struct {
	CC   ipmi.CompletionCode
	Data []byte
}

func (r *DellOEMResponse) CompletionCode() ipmi.CompletionCode { return r.CC }
func (r *DellOEMResponse) CompletionCodes() map[uint8]string   { return map[uint8]string{} }
func (r *DellOEMResponse) Unpack(d []byte) error {
	if len(d) > 0 {
		r.CC = ipmi.CompletionCode(d[0])
		r.Data = d[1:]
	}
	return nil
}
func (r *DellOEMResponse) Format() string { return "" }

func sendRawCmd(ctx context.Context, client *ipmi.Client, netFn, cmd uint8, data []byte) error {
	req := &DellOEMRequest{NetFn: netFn, Cmd: cmd, Data: data}
	res := &DellOEMResponse{}
	if err := client.Exchange(ctx, req, res); err != nil {
		return err
	}
	if res.CompletionCode() != ipmi.CompletionCode(0) {
		return fmt.Errorf("IPMI Error: 0x%02x", res.CompletionCode())
	}
	return nil
}

func setIPMIDynamicControl(ctx context.Context, client *ipmi.Client, enable bool) error {
	val := byte(0x00)
	if enable {
		val = 0x01
	}
	return sendRawCmd(ctx, client, 0x30, 0x30, []byte{0x01, val})
}

func setIPMIFanSpeed(ctx context.Context, client *ipmi.Client, speed int) error {
	return sendRawCmd(ctx, client, 0x30, 0x30, []byte{0x02, 0xff, byte(speed)})
}

// --- 状态与Web ---

func updateStateMetrics(m MetricResult) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.CurveTemp = m.CurveTemp
	state.SafeTemp = m.SafeTemp
	state.PowerUsage = m.Power
	state.LastUpdated = time.Now()
	state.LastError = ""
}

func updateStateMode(mode string, speed int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Mode = mode
	state.FanSpeedPct = speed
}

func handleError(err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.LastError = err.Error()
	state.LastUpdated = time.Now()
}

func startWebServer(bind, port string) {
	fsys, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return
	}
	http.Handle("/", http.FileServer(http.FS(fsys)))
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})
	http.ListenAndServe(bind+":"+port, nil)
}
