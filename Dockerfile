# --- 第一阶段：构建 (Builder) ---
FROM golang:1.24-alpine AS builder

# 安装 git (go mod download 需要)
RUN apk add --no-cache git

# 设置工作目录
WORKDIR /app

# 1. 先复制依赖文件，利用 Docker 缓存层
COPY go.mod ./

# 下载依赖
RUN go mod tidy && go mod download

# 2. 复制源代码和静态资源
COPY main.go .
COPY static/ static/

# 3. 编译 Go 程序
# CGO_ENABLED=0 确保生成静态链接的二进制文件
RUN CGO_ENABLED=0 go build -o fanctl main.go

# --- 第二阶段：运行 (Runner) ---
FROM scratch

# 添加元数据
LABEL maintainer="iDRAC Fan Controller"

# 设置工作目录
WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/fanctl .

# 暴露 Web 端口
EXPOSE 8080

# 设置容器启动命令
ENTRYPOINT ["./fanctl"]