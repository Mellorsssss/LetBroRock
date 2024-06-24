usleep 2000
PID=$(pgrep foo)
if [ ${#PID} -eq 0 ]
then
    echo "observer is not running"
    exit -1
fi
#perf record -F 99 -g -p $PID -- sleep $1
perf record -F 99 -g -p $PID -- sleep 10
#perf  record  -g  --call-graph  fp  -e  instructions:u  -p $1  -b  -Fmax -- sleep 10
