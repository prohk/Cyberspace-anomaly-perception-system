do{
$c = Get-Counter -Counter "\Processor(_Total)\% Processor Time" | foreach {$_.CounterSamples[0].CookedValue}
#write-host $c
#gwmi 取出总得内存和可以使用的内存,结合算出内存的使用率
$mem1 =0 + (gwmi win32_OperatingSystem).TotalVisibleMemorySize
$mem2 =0 + (gwmi win32_OperatingSystem).FreePhysicalMemory
$mem = [Math]::round((($mem1 - $mem2)/$mem1) * 100 ,3  )
#write-host $mem
#监控磁盘空间
$diskcount =  Get-WmiObject win32_logicaldisk  |  Where-Object {$_.drivetype -eq 3}
foreach ($item in $diskcount)
{
$t = $item.DeviceID
$diskname = "'" + $t.substring(0,1) + "'"
$diskspace1 = 0 + $item.FreeSpace
$diskspace2 = 0 + $item.size
$diskspace = [Math]::Round( (($diskspace1 /$diskspace2) * 100) , 3)
#write-host $diskname
#write-host $diskspace
if ($diskspace -lt 10)
{
$msg = "diskwarn: 主机剩余磁盘空间少于10%!"
$msg
}
}

if ($mem -gt 80)
{
$msg1 = "memwarn: 内存使用量大于80%!"
$msg1
}
if ($c -gt 70)
{
$msg3 = "cpuwarn: cpu使用量大于70%!"
$msg3
}
Start-Sleep -s 60
}
while(1 -eq 1)