#!/bin/bash
# Nscan Proxy 停止脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/llm_proxy.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "Nscan Proxy 未运行"
    exit 0
fi

PID=$(cat "$PID_FILE")
if ! ps -p "$PID" > /dev/null 2>&1; then
    echo "Nscan Proxy 未运行 (PID: $PID)"
    rm -f "$PID_FILE"
    exit 0
fi

echo "停止 Nscan Proxy (PID: $PID)..."
kill "$PID"

# 等待进程结束
for i in {1..10}; do
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "✅ Nscan Proxy 已停止"
        rm -f "$PID_FILE"
        exit 0
    fi
    sleep 1
done

# 强制停止
echo "强制停止 Nscan Proxy..."
kill -9 "$PID"
rm -f "$PID_FILE"
echo "✅ Nscan Proxy 已强制停止"
