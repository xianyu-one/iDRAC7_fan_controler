# --- 第一阶段：构建 (Builder) ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

# 3. 复制源代码和静态资源
COPY main.go .
COPY static/ static/

# 4. 编译
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