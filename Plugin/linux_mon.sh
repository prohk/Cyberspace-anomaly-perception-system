#!/bin/bash

#cpu使用阈值
cpu_warn='75'
#mem空闲阈值
mem_warn='100'
#disk使用阈值
disk_warn='90'
#---cpu
item_cpu () {
cpu_idle=`top -b -n 1 | grep Cpu | awk '{print $8}'|cut -f 1 -d "."`
cpu_use=`expr 100 - $cpu_idle`
if [[ $cpu_use -gt $cpu_warn ]]
    then
        echo "cpu warning!!!"
    else
        echo "cpu ok!!!"
fi
}
#---mem
item_mem () {
#MB为单位
mem_free=`free -m | grep "Mem" | awk '{print $4+$6}'`
if [[ $mem_free -lt $mem_warn  ]]
    then
        echo "mem warning!!!"
    else
        echo "mem ok!!!"
fi
}
while True;do
item_cpu
item_mem
sleep 60s
done
