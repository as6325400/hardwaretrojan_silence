#!/bin/bash

# 檢查是否有輸入檔案
if [ "$#" -ne 1 ]; then
    echo "使用方法: $0 <your_circuit.bench>"
    exit 1
fi

INPUT_FILE=$1

# 執行 ABC 指令
# 使用 ' ' 代替橫線避免 echo 報錯
abc -q "
  read_bench $INPUT_FILE;
  echo Original_Status;
  print_stats;
  
  sweep;
  cleanup;
  
  echo After_Cleanup;
  print_stats;
"