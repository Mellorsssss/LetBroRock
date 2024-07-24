usleep 2000
#perf record -F 99 -g -p $PID -- sleep $1
#perf record -F 99 -g -p $PID -- sleep 10
perf  record  -g  --call-graph  fp  -e  instructions:u    -Fmax -- ./foo 4
