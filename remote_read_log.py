import paramiko
import select
import re
import app
import datetime
from dateutil import parser

def link_server_client(serverip, user, pwd, cmd, key):
    print('--开始链接服务器%s' % serverip)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print('--开始认证--')
    try:
        client.connect(serverip, 22, username=user, password=pwd, timeout=10)
    except Exception:
        print("服务器%s连接失败"%serverip)
        return
    print('--认证成功--')
    transport = client.get_transport()  # 返回SSH的连接对象
    channel = transport.open_session()  # 创建管道
    channel.get_pty()  # 激活一个终端
    channel.exec_command(cmd)
    while True:
        if channel.exit_status_ready():
            break
        try:
            rl, wl, el = select.select([channel], [], [])  # select io处理模块
            if len(rl) > 0:
                recv = channel.recv(1024)
                recv = recv.decode('utf-8', 'ignore')  # ignore  忽略其中有异常的编码
                if key == 'auth':
                    module_login(recv, serverip)
                elif key == 'mondir':
                    mon_dir(recv, serverip)
                elif key == 'custom':
                    app.push_log('服务器%s连接成功'%serverip,'connect')
                    app.push_log(recv, 'login')
                elif key == 'ids':
                    ls_idslog = [2, 3, 4, 4, 6]
                    log_array = str_split(recv, key)
                    log_array = remove_arr(log_array, ls_idslog)
                    if log_array[1] == 'pri=5' or log_array == 'pri=4':
                        msg = ids_module(log_array)
                        print(msg)
                        app.push_log(msg, 'ids')
                elif key == 'virus':
                    ls_viruslog = [1, 3, 4, 4, 4, 4]
                    log_array = str_split(recv, key)
                    log_array = remove_arr(log_array, ls_viruslog)
                    if log_array[4] == '查杀修复失败':
                        msg = virus_module(log_array)
                        print(msg)
                        app.push_log(msg, 'virus')
                elif key == 'bussiness':
                    pass
                elif key == 'monlinux_usage':
                    if 'mem warning' in recv:
                        print(recv)
                        # mem_free = re_handle("--(.*)--",recv)
                        current_time = datetime.datetime.now()
                        msg = "警告:%s linux主机%s 内存使用异常超出阈值！"%(current_time,serverip)
                        data = "'%s','%s','%s','%s'" % (serverip, current_time, msg, '内存异常')
                        app.db_insert('所有告警日志', data)
                        app.push_log(msg,'ids')
                    elif 'cpu warning' in recv:
                        # cpu_usage = re_handle("--(.*)--",recv)
                        current_time = datetime.datetime.now()
                        msg = "警告:%s linux主机%s cpu使用异常超出阈值！"%(current_time,serverip)
                        data = "'%s','%s','%s','%s'" % (serverip, current_time, msg, 'cpu异常')
                        app.db_insert('所有告警日志', data)
                        app.push_log(msg, 'ids')
                    print(recv)
                elif key == 'monwin_usage':
                    if 'mem' in recv:
                        current_time = datetime.datetime.now()
                        msg = "警告:%s win主机%s 内存使用异常超出阈值!"%(current_time,serverip)
                        data = "'%s','%s','%s','%s'" % (serverip, current_time, msg, '内存异常')
                        app.db_insert('所有告警日志', data)
                        app.push_log(msg,'virus')
                    elif 'cpu' in recv:
                        current_time = datetime.datetime.now()
                        msg = "警告:%s win主机%s cpu使用异常超出阈值!" % (current_time, serverip)
                        data = "'%s','%s','%s','%s'" % (serverip, current_time, msg, 'cpu异常')
                        app.db_insert('所有告警日志', data)
                        app.push_log(msg,'virus')
                    print(recv)
                file_save(recv, 'log %s .txt' % (serverip))

        except KeyboardInterrupt:  # 遇到Control-C就退出
            print("Caught Control-C")
            channel.send("\x03")
            channel.close()


def file_save(content, filename, mode='a'):
    with open(filename, mode) as f:
        for i in content:
            f.writelines(i)


def module_login(str, serverip):
    ip_re = ".*[\s:](\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}).*"
    entry_re = ".*([ssh|vnc|rdp]{3,5}).*"
    auth_user_re = ".*for.{1}(.+).{1}from.*"
    cureent_time_re = "([Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec]{3,4}\s+\d{1,2}\s.+?)\s.*"
    if 'Failed password' in str:  # 破解行为事件
        global repeat_ls
        global count
        global start_time
        real_time = datetime.datetime.now()
        srcip = re_handle(ip_re, str)
        entry = re_handle(entry_re, str)
        auth_user = re_handle(auth_user_re, str)
        cureent_time = re_handle(cureent_time_re, str)
        cureent_time = time_format(cureent_time)
        msg = "警告:%s 主机%s受到来自%s的%s登陆对用户%s破解行为" % (cureent_time, serverip, srcip, entry, auth_user)
        tmp_ls = [serverip,entry,srcip]
        print(tmp_ls)
        if tmp_ls in repeat_ls:
            count += 1
            if count >= 5:
                print(count)
                msg = "警告:%s 主机%s受到来自%s的%s登陆对用户%s破解行为 次数%s次" % (cureent_time, serverip, srcip, entry, auth_user,count)
                data = "'%s','%s','%s','%s'" % (serverip, cureent_time, msg, count)
                data2 = "'%s','%s','%s','%s'" % (srcip, cureent_time, msg, '破解行为')
                app.db_insert('破解行为', data)
                app.db_insert('所有告警日志',data2)
                print(msg)
                app.push_log(msg, 'login')
        else:
            repeat_ls.append(tmp_ls)
        print(repeat_ls)
        now_hour = parser.parse(cureent_time).strftime('%H')
        jiange = int(now_hour) - int(start_time)
        if jiange >= 3:
            repeat_ls.clear()
            start_time = now_hour
            print(start_time)

    elif 'Accepted password' in str:  # 登陆成功事件
        srcip = re_handle(ip_re, str)
        entry = re_handle(entry_re, str)
        cureent_time = re_handle(cureent_time_re, str)
        cureent_time = time_format(cureent_time)
        msg = "警告:%s 主机%s 受到来自%s的%s登陆成功！" % (cureent_time, serverip, srcip, entry)
        data = "'%s','%s','%s','%s登陆成功'"%(serverip,cureent_time,msg,entry)
        app.db_insert('linux_log',data)
        print(msg)
        app.push_log(msg, 'login')
    elif 'telnet' in str:  # telnet登陆事件
        cureent_time = re_handle(cureent_time_re, str)
        cureent_time = time_format(cureent_time)
        srcip = re_handle(ip_re, str)
        msg = "警告: %s 主机 %s 收到来自%s 的telnet登陆" % (cureent_time, serverip, srcip)
        data = "'%s','%s','%s','telnet登陆'" % (serverip, cureent_time, msg)
        app.db_insert('linux_log', data)
        print(msg)
        app.push_log(msg, 'login')
    else:
        return


def re_handle(cmpstr, str):
    result = re.match(cmpstr, str)
    if result:
        result = result.group(1)
        return result
    else:
        return


def time_format(str):
    time_par = parser.parse(str)
    time = time_par.strftime('%Y-%m-%d %H:%M:%S')
    return time


def mon_dir(str, serverip):
    filename_re = ".*\s(.+)\sMODIFY.*"
    time_re = "(\d{2}[/]\d{2}[/]\d{2}\s\d{2}[:]\d{2})"
    time = re_handle(time_re, str)
    filename = re_handle(filename_re, str)
    msg = "警告：%s 探测到目标服务器 %s 关键配置 %s 变更！ " % (time, serverip, filename)
    data = "'%s','%s','%s','关键配置变更'" % (serverip,time,msg)
    app.db_insert('linux_log', data)
    app.push_log(msg, 'config_modify')


class abnormal_business():
    def __init__(self, ip, user,):
        self.trust_ip = ip
        self.trust_user = user


    def is_blockedauth(self, str):
        if '已锁定账户' in str:
            blockeduser_re = ".*[(.+)].*"
            blockeduser = re_handle(blockeduser_re, str)
            current_time = datetime.datetime.now()
            msg = "%s警告：业务系统发生对已锁定账户 %s 的登陆行为" % (current_time, blockeduser)
            print(msg)
            app.push_log(msg,'business')
        else:
            return

    def is_dangerlogin(self,str):
        if 'manager' in str:
            ip_re = ".*(\d{2,3}[.]\d{2,3}[.]\d{2,3}[.]\d{2,3}).*"
            date_re = ".*(\d{2}[/].*\d{4}[:]\d{2}[:]\d{2}[:]\d{2}).*"
            ip = re_handle(ip_re,str)
            if ip not in self.trust_ip:
                date = re_handle(date_re,str)
                if ip:
                    msg = "%s警告：业务系统发生来自%s应用账号异常IP登陆成功"
                    print(msg)
                    app.push_log(msg,'business')
            else:
                print('合法IP登陆业务系统成功')
        else:
            return

    def is_erroraddr(self, str):
        # 私有地址段：10.0.0.0 -10.255.255.255
        # 172.16.0.0 -172.31.255.255
        # 192.168.0.0 -192.168.255.255
        ip_re = ".*?(\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}).*"
        ip = re_handle(ip_re, str)
        user_re = ".*[(.+)].*"
        user = re_handle(user_re, str)
        part1_re = "^(\d{1,3})[.].*"
        part2_re = "^\d{1,3}[.]?(\d{1,3})[.]"
        firstpart = re_handle(part1_re, ip)
        secpart = re_handle(part2_re, ip)
        secpart = int(secpart)
        if firstpart == '10':
            pass
        elif firstpart == '10' and 16 <= secpart <= 31:
            pass
        elif firstpart == '10' and secpart == 168:
            pass
        else:
            now_time = datetime.datetime.now()
            msg = "%s警告: 用户 %s 登陆的地址为非内网IP %s" % (now_time, user, ip)
            print(msg)
            app.push_log(msg,'business')


def update_date(str, key):
    nowtime = datetime.datetime.now()
    time1 = datetime.datetime.strftime(nowtime, '%Y-%m-%d')
    str_log = str + '.%s.%s' % (time1, key)
    return str_log


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
    return msg


def ids_module(ls):
    op = ls[6]
    if op == '''op="permit"''':
        time_re = ".*(\d{4}[-]\d{2}[-]\d{2}\s\d{2}[:]\d{2}[:]\d{2}).*"
        time = re.match(time_re,ls[0]).group(1)
        srcip = ls[3].replace("src=","")
        dstip = ls[4].replace("dst=","")
        types = ls[7].replace("msg=","")
        msg = "警告:%s 主机%s 受到来自 %s 的 %s"%(time,srcip,dstip,types)
        print(msg)
        return msg
    else:
        return

count = 1
start_time = 0
end_time = 0
repeat_ls = []
catalina_name = update_date('catalina', 'log')
log_name = update_date('localhost_access_log', 'txt')
print(catalina_name)
print(log_name)

