#!/bin/bash
# LLM Proxy Hub 启动脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 检查是否已经运行
PID_FILE="$SCRIPT_DIR/llm_proxy.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "LLM Proxy Hub 已经在运行 (PID: $PID)"
        echo "如需重启，请先运行: ./stop.sh"
        exit 1
    fi
fi

# 启动服务
echo "启动 LLM Proxy Hub..."
nohup python start_proxy.py > proxy.log 2>&1 &
NEW_PID=$!
echo $NEW_PID > "$PID_FILE"

# 等待服务启动
sleep 3

# 检查是否启动成功
if ps -p "$NEW_PID" > /dev/null 2>&1; then
    echo "✅ LLM Proxy Hub 已启动 (PID: $NEW_PID)"
    echo "📊 Web 面板: http://127.0.0.1:8888"
    echo "📝 日志文件: $SCRIPT_DIR/proxy.log"
else
    echo "❌ 启动失败，请检查日志: $SCRIPT_DIR/proxy.log"
    rm -f "$PID_FILE"
    exit 1
fi
