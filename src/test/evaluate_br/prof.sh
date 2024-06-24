perf  record  -g  --call-graph  fp  -e  br_inst_retired.near_taken:uppp    -b  -Fmax ./foo $1
perf  script  -F  ip,brstack  -i  perf.data  --show-mmap-event  &>  perf.script
