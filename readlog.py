import os
import tailer
from multiprocessing import Pool
import app
import re
from remote_read_log import abnormal_business


def follow_log(file,key):
    if os.path.exists(file):
        if key == 'virus':
            print('防病毒日志文件开始读取')
        elif key == 'ids':
            print('ids日志开始读取')
    else:
        print('没有找到该日志')
        return
    for line in tailer.follow(open(file, encoding='utf-8', buffering=516)):
        if key == 'virus':
            ls_viruslog = [1, 3, 4, 4, 4, 4]
            log_array = str_split(line, key)
            log_array = remove_arr(log_array, ls_viruslog)
            if log_array[4]=='查杀修复失败':
                msg = virus_module(log_array)
                print(msg)
                app.push_log(msg,'virus')
        elif key == 'ids':
            ls_idslog = [2, 3, 4, 4, 6]
            log_array = str_split(line, key)
            log_array = remove_arr(log_array, ls_idslog)
            if log_array[1] == 'pri=5' or log_array == 'pri=4':
                msg = ids_module(log_array)
                print(msg)
                app.push_log(msg,'ids')
        elif key == 'business':
            trust_ip = ['203.168.15.109']
            business_event = abnormal_business(ip=trust_ip,user='root')
            business_event.is_dangerlogin(line)
            business_event.is_blockedauth(line)



def remove_arr(array,ls):
    if len(array)>9:
        for i in ls:
            del array[i]
        return array
    else:
        print('异常日志输入,跳过')

def str_split(line,key):
    if key == 'virus':
        array = line.split("\t")
    elif key == 'ids':
        array = line.split(", ")
    return array


def virus_module(ls):
    time = ls[0]
    ip = ls[1]
    type = ls[3]
    result = ls[4]
    msg = "警告:%s 主机%s 感染%s %s!"%(time,ip,type,result)
    data = "'%s','%s','%s','%s'" % (ip, time, msg, '病毒感染')
    app.db_insert('所有告警日志',data)
    return msg


def ids_module(ls):
    op = ls[6]
    if op == '''op="permit"''':
        time_re = ".*(\d{4}[-]\d{2}[-]\d{2}\s\d{2}[:]\d{2}[:]\d{2}).*"
        time = re.match(time_re,ls[0]).group(1)
        srcip = ls[3].replace("src=","")
        dstip = ls[4].replace("dst=","")
        types = ls[7].replace("msg=","")
        msg = "警告:%s 主机%s 受到来自 %s 的 %s"%(time,dstip,srcip,types)
        print(msg)
        return msg
    else:
        return

# key=['virus','ips']
# ls_viruslog=[1,3,4,4,4,4]
# ls_ips = [2,3,4,4,6]
# virus_log = "msg.txt"
# ddos_log = "ddos_log.txt"
#


if __name__ == "__main__":
    p=Pool(2)
    p.apply_async(follow_log,args=(ddos_log,ls_ips,key[1]))
    p.apply_async(follow_log,args=(virus_log,ls_viruslog, key[0]))
    p.close()
    p.join()


#



