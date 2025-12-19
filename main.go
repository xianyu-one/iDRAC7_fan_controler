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
	defaultWebBind      = "127.0.0.1"
	defaultWebPort      = "8080"
	defaultFanCurve     = "1-14:10,15-19:15,20-24:20,25-29:25,30-34:30"
	defaultTempSensor   = "04h" // 进气口温度
	defaultThreshold    = 35    // 摄氏度
	defaultIPMIPort     = 623
)

// Config 存储配置
type Config struct {
	Host         string
	User         string
	Password     string
	Port         int
	SensorID     int
	Threshold    int
	PollInterval time.Duration
	WebBind      string
	WebPort      string
	FanCurve     []FanRule
	Insecure     bool

	// 校准参数
	Scale  float64
	Offset int
}

// FanRule 风扇规则
type FanRule struct {
	MinTemp int
	MaxTemp int
	Speed   int
}

// AppState 运行时状态
type AppState struct {
	mu          sync.RWMutex
	CurrentTemp int       `json:"current_temp"`
	FanSpeed    int       `json:"fan_speed"`
	Mode        string    `json:"mode"`
	LastUpdated time.Time `json:"last_updated"`
	LastError   string    `json:"last_error,omitempty"`
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动 Web 服务器 (独立 goroutine)
	go startWebServer(cfg.WebBind, cfg.WebPort)

	log.Printf("正在启动 iDRAC 风扇控制 (长连接模式, 目标: %s:%d, 间隔: %s)", cfg.Host, cfg.Port, cfg.PollInterval)
	if cfg.Scale != 1.0 || cfg.Offset != 0 {
		log.Printf("启用温度校准: 原始值 * %.2f + (%d)", cfg.Scale, cfg.Offset)
	}
	runPersistentControlLoop(ctx, cfg)
}

// --- 配置逻辑 ---

func parseConfig() (*Config, error) {
	cfg := &Config{}

	host := flag.String("ip", os.Getenv("IDRAC_IP"), "iDRAC IP 地址")
	user := flag.String("user", os.Getenv("IDRAC_USER"), "iDRAC 用户名")
	pass := flag.String("password", os.Getenv("IDRAC_PASSWORD"), "iDRAC 密码")
	sensorStr := flag.String("sensor", getEnvOrDefault("TEMP_SENSOR", defaultTempSensor), "温度传感器 ID")
	bind := flag.String("bind", getEnvOrDefault("WEB_BIND", defaultWebBind), "Web 监听地址")
	port := flag.String("port", getEnvOrDefault("WEB_PORT", defaultWebPort), "Web 端口")
	intervalStr := flag.String("interval", getEnvOrDefault("POLL_INTERVAL", "30s"), "轮询间隔")
	curveStr := flag.String("curve", getEnvOrDefault("FAN_CURVE", defaultFanCurve), "风扇曲线")

	// 校准参数
	scaleStr := flag.Float64("scale", 1.0, "温度比例系数 (默认 1.0)")
	offsetStr := flag.Int("offset", 0, "温度偏移量 (默认 0)")

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
		return nil, fmt.Errorf("缺少必要的凭据 (ip, user, password)")
	}

	cfg.Host = *host
	cfg.User = *user
	cfg.Password = *pass
	cfg.Port = defaultIPMIPort
	cfg.WebBind = *bind
	cfg.WebPort = *port
	cfg.Threshold = defaultThreshold
	cfg.Scale = *scaleStr
	cfg.Offset = *offsetStr

	sensorID, err := parseHexID(*sensorStr)
	if err != nil {
		return nil, fmt.Errorf("无效的传感器 ID: %v", err)
	}
	cfg.SensorID = sensorID

	dur, err := time.ParseDuration(*intervalStr)
	if err != nil {
		return nil, fmt.Errorf("无效的时间间隔格式: %v", err)
	}
	cfg.PollInterval = dur

	rules, err := parseFanCurve(*curveStr)
	if err != nil {
		return nil, fmt.Errorf("无效的风扇曲线: %v", err)
	}
	cfg.FanCurve = rules

	return cfg, nil
}

func parseHexID(s string) (int, error) {
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

// --- 控制逻辑 (长连接版) ---

func runPersistentControlLoop(ctx context.Context, cfg *Config) {
	var client *ipmi.Client
	var err error

	// 创建定时器
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	// 信号处理
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// 辅助函数：安全关闭连接
	closeClient := func() {
		if client != nil {
			// 尝试关闭会话，忽略错误
			_ = client.Close(context.Background())
			client = nil
		}
	}

	// 退出时的清理
	defer func() {
		log.Println("程序正在退出...")
		if client != nil {
			log.Println("尝试恢复动态控制...")
			_ = setIPMIDynamicControl(context.Background(), client, true)
			closeClient()
		}
	}()

	for {
		// 1. 确保连接存在
		if client == nil {
			log.Println("正在连接 iDRAC...")
			client, err = ipmi.NewClient(cfg.Host, cfg.Port, cfg.User, cfg.Password)
			if err != nil {
				handleError(fmt.Errorf("客户端创建失败: %v", err))
				goto WAIT
			}

			// 连接超时设置
			connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
			if err := client.Connect(connCtx); err != nil {
				connCancel()
				handleError(fmt.Errorf("连接失败: %v (请检查密码或并发会话数)", err))
				closeClient()
				goto WAIT
			}
			connCancel()
			log.Println("iDRAC 连接成功")
		}

		// 2. 执行逻辑
		{
			// 给单次操作设置超时，防止卡死
			opCtx, opCancel := context.WithTimeout(ctx, 5*time.Second)
			err = processCycleOnce(opCtx, client, cfg)
			opCancel()

			if err != nil {
				handleError(err)
				// 如果是网络或会话错误，关闭连接以便下次重连
				log.Println("操作失败，重置连接...")
				closeClient()
			}
		}

	WAIT:
		select {
		case <-ctx.Done():
			return
		case <-sigs:
			return // 触发 defer
		case <-ticker.C:
			// 继续下一次循环
		}
	}
}

func processCycleOnce(ctx context.Context, client *ipmi.Client, cfg *Config) error {
	// 1. 获取温度
	temp, rawVal, err := getIPMITemperature(ctx, client, cfg.SensorID, cfg.Scale, cfg.Offset)
	if err != nil {
		return fmt.Errorf("读取温度失败: %w", err)
	}

	updateStateTemp(temp)

	// --- 智能校准提示 ---
	// 如果读数 > 100°C 且未设置 Offset，极大可能是因为没有减去 128
	// 此时如果不处理，逻辑会认为系统过热 (144 > 35) 从而触发动态控制（全速）
	if temp > 100 && cfg.Offset == 0 {
		log.Printf("⚠️  警告: 读取到异常高温 (%d°C)！", temp)
		log.Printf("⚠️  分析: 原始值 %d 减去 128 后为 %d°C，这通常是 Dell 12G 服务器的预期值。", rawVal, rawVal-128)
		log.Printf("⚠️  建议: 请立即停止程序，并添加参数重启: -offset -128")

		// 临时保护：在这种极端异常下，我们暂时认为它是误报，不强制切回动态控制，
		// 而是尝试用修正后的值来跑一次逻辑，避免风扇无故狂转。
		// 但为了安全，如果修正后还是高，我们就不管了。
		correctedTemp := temp - 128
		if correctedTemp < cfg.Threshold {
			log.Printf("⚠️  [临时自动修正] 使用 %d°C 进行本次风扇控制...", correctedTemp)
			temp = correctedTemp
		}
	}

	// 2. 控制风扇
	if temp >= cfg.Threshold {
		if state.Mode != "动态" {
			log.Printf("温度 %d°C (原始值: %d) >= %d°C. 启用动态控制。", temp, rawVal, cfg.Threshold)
			if err := setIPMIDynamicControl(ctx, client, true); err != nil {
				return fmt.Errorf("启用动态控制失败: %w", err)
			}
			updateStateMode("动态", 0)
		}
	} else {
		targetSpeed := calculateFanSpeed(temp, cfg.FanCurve)

		// 每次都强制写入，防止被其他机制覆盖
		if err := setIPMIDynamicControl(ctx, client, false); err != nil {
			return fmt.Errorf("禁用动态控制失败: %w", err)
		}

		if err := setIPMIFanSpeed(ctx, client, targetSpeed); err != nil {
			return fmt.Errorf("设置风扇转速失败: %w", err)
		}

		log.Printf("温度: %d°C (原始值: %d). 设置风扇转速: %d%%", temp, rawVal, targetSpeed)
		updateStateMode("手动", targetSpeed)
	}
	return nil
}

func handleError(err error) {
	log.Printf("错误: %v", err)
	updateStateError(err)
}

func calculateFanSpeed(temp int, rules []FanRule) int {
	for _, rule := range rules {
		if temp >= rule.MinTemp && temp <= rule.MaxTemp {
			return rule.Speed
		}
	}
	if len(rules) > 0 {
		return rules[0].Speed
	}
	return 20
}

// --- IPMI 交互 ---

func getIPMITemperature(ctx context.Context, client *ipmi.Client, sensorID int, scale float64, offset int) (int, int, error) {
	reading, err := client.GetSensorReading(ctx, uint8(sensorID))
	if err != nil {
		return 0, 0, err
	}

	rawVal := int(reading.Reading)

	// 应用校准公式：Raw * Scale + Offset
	// 注意：先应用 Scale，再加 Offset
	calcVal := int(float64(rawVal)*scale) + offset

	return calcVal, rawVal, nil
}

// --- 自定义 Raw 命令实现 ---

type DellOEMRequest struct {
	NetFn uint8
	Cmd   uint8
	Data  []byte
}

func (req *DellOEMRequest) Command() ipmi.Command {
	return ipmi.Command{
		NetFn: ipmi.NetFn(req.NetFn),
		ID:    req.Cmd,
	}
}

func (req *DellOEMRequest) Pack() []byte {
	return req.Data
}

type DellOEMResponse struct {
	CompletionCodeVal ipmi.CompletionCode
	Data              []byte
}

func (res *DellOEMResponse) CompletionCode() ipmi.CompletionCode {
	return res.CompletionCodeVal
}

func (res *DellOEMResponse) CompletionCodes() map[uint8]string {
	return map[uint8]string{}
}

func (res *DellOEMResponse) Unpack(data []byte) error {
	if len(data) > 0 {
		res.CompletionCodeVal = ipmi.CompletionCode(data[0])
		res.Data = data[1:]
	}
	return nil
}

func (res *DellOEMResponse) Format() string {
	return fmt.Sprintf("Code: %02x, Data: %x", res.CompletionCodeVal, res.Data)
}

func sendRawCmd(ctx context.Context, client *ipmi.Client, netFn uint8, cmd uint8, data []byte) error {
	req := &DellOEMRequest{
		NetFn: netFn,
		Cmd:   cmd,
		Data:  data,
	}
	res := &DellOEMResponse{}

	err := client.Exchange(ctx, req, res)
	if err != nil {
		return err
	}

	if res.CompletionCode() != ipmi.CompletionCode(0x00) {
		return fmt.Errorf("IPMI 命令失败，完成代码: 0x%02x", res.CompletionCode())
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

func setIPMIFanSpeed(ctx context.Context, client *ipmi.Client, speedPercent int) error {
	return sendRawCmd(ctx, client, 0x30, 0x30, []byte{0x02, 0xff, byte(speedPercent)})
}

// --- 状态管理 ---

func updateStateTemp(temp int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.CurrentTemp = temp
	state.LastUpdated = time.Now()
	state.LastError = ""
}

func updateStateMode(mode string, speed int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Mode = mode
	state.FanSpeed = speed
}

func updateStateError(err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.LastError = err.Error()
	state.LastUpdated = time.Now()
}

// --- Web 服务器 ---

func startWebServer(bind, port string) {
	fsys, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Printf("无法加载静态文件: %v", err)
		return
	}

	http.Handle("/", http.FileServer(http.FS(fsys)))
	http.HandleFunc("/api/status", handleStatus)

	addr := bind + ":" + port
	log.Printf("Web 仪表盘已启动: http://%s", addr)
	// 移除了 Fatalf，防止端口错误导致主程序退出
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Web 服务器启动失败 (非致命): %v", err)
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}
