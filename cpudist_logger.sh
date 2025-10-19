#!/bin/bash

# 日志文件夹
LOGDIR="./cpudist_logs"

# 创建日志文件夹（如果不存在）
mkdir -p "$LOGDIR"

# 当前日期，用作日志文件名
DATE=$(date +%F)  # 格式：YYYY-MM-DD

# 日志文件
LOGFILE="$LOGDIR/cpudist_8000_$DATE.log"

# 监控间隔（秒）
INTERVAL=5
# 输出次数
COUNT=20

echo "Monitoring all processes listening on port 8000..."
echo "Logging to $LOGFILE"

# 获取所有监听 8000 端口的 PID
PIDS=$(lsof -ti:8000)

if [ -z "$PIDS" ]; then
    echo "No process is listening on port 8000"
    exit 1
fi

echo "Found PIDs: $PIDS"

# 循环每个 PID
for PID in $PIDS; do
    echo "Starting cpudist monitoring for PID $PID..."
    # 后台运行 cpudist，输出追加到日志文件
    nohup python3 cpudist.py -p "$PID" -T $INTERVAL $COUNT >> "$LOGFILE" 2>&1 &
done

echo "Monitoring started for all PIDs."
