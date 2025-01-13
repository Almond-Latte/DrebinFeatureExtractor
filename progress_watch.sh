#!/bin/bash

# ./malware のファイル数をキャッシュ
total=$(find ./cleanware -type f | wc -l)

if [ "$total" -eq 0 ]; then
    echo "No files to process in ./cleanware"
    exit 1
fi

# 進捗を表示
while true; do
    finished=$(find ./report_cleanware/ -type f | wc -l)
    percent=$(echo "scale=5;$finished / $total * 100" | bc)
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "[%s] Progress: %.2f%% (%d/%d files)\n" "$timestamp" "$percent" "$finished" "$total"
    sleep 60
done

