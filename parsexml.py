from lxml import etree
import socket
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

def read_json(file):
    with open(file, 'r')as f:
        event = ijson.items(f, "Event.System")
        for row,value in event:
            if row['System']['EventID'] == '4624':
                print(row)


def xml_handle(file):
    with open(file, 'r',encoding='utf-8') as f:
        with open(newxml, 'w',encoding='utf-8') as g:
            g.write('           ')
            for line in f:
                if '<?xml version=\"1.0\" encoding=\"utf-8\"?>' not in line:
                    g.write(line)
            write_head(newxml)


# 想要使用多次IO流，必须不在一个函数内
def write_head(file):
    with open(file, 'r+')as h:
        h.seek(0, 0)
        h.write('<xmldata>\n')


def write_tail(file):
    g = open(file, 'a',encoding='utf-8')
    g.write('\n</xmldata>')
    g.close()



def check_susscess(str):
    if str == "4625":
        return "失败"
    elif str == "4624":
        return "成功"
    else:
        return "失败"


def lxml_handle(file,ip,last_event):
    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
    tree = etree.parse(file)
    root = tree.getroot()
    events = root.iterchildren()
    record_ls = []
    result = 0
    current_time = 0
    srcip = 0
    user = 0
    for event in events:
        test = event.iter(tag='%sEventData'%ns)
        for evdata in event.iterchildren(tag='%sEventData'%ns):
            for data in evdata.iterchildren(tag='%sData'%ns):

                if data.get('Name')=="LogonType":
                    keyele = data.getparent()
                    thisevent = keyele.getparent()
                    systemtag = thisevent[0]
                    if int(systemtag[8].text) <= last_event:
                        break
                    if data.text == '8':
                        for it in systemtag:
                            systemdata1 = it.iter(
                                tag=('%sEventID' % ns, '%sTimeCreated' % ns, '%sEventRecordID' % ns))
                            for key in systemdata1:
                                if key.tag == '%sEventID'%ns:
                                    eventid = key.text
                                    result = check_susscess(eventid)
                                if key.tag == '%sTimeCreated'%ns:
                                    current_time = key.get("SystemTime")
                                if key.tag == '%sEventRecordID'%ns:
                                    recordid = key.text
                                    record_ls.append(int(recordid))
                                msg = "警告:%s 探测到主机 %s 被SSH登陆%s"%(current_time,ip,result)
                                print(msg)
                                with open("eventdata.txt","a",encoding='gbk')as f:
                                    f.write(msg+'\n')
                    elif data.text == '10':
                        for systemit in systemtag:
                            systemdata = systemit.iter(
                                tag=('%sEventID' % ns, '%sTimeCreated' % ns, '%sEventRecordID' % ns))
                            for key in systemdata:
                                if key.tag == '%sEventID'%ns:
                                    eventid = key.text
                                    result = check_susscess(eventid)
                                if key.tag == '%sTimeCreated'%ns:
                                    current_time = key.get("SystemTime")
                                if key.tag == '%sEventRecordID'%ns:
                                    recordid = key.text
                                    record_ls.append(int(recordid))
                        keydata = keyele.iter()
                        for child in keydata:
                            if child.get('Name')=='IpAddress':
                                srcip = child.text
                                # print(ip)
                            if child.get('Name')=='TargetUserName':
                                user = child.text
                                # print(user)
                        msg = "警告: %s 检测到主机 %s 来自 %s 对用户%s远程登陆%s"%(current_time,ip,srcip,user,result)
                        print(msg)
                        #注意，远程打开windows的文件可能会出现命令行编码问题，具体解决方法百度
                        with open("eventdata.txt","a",encoding='gbk')as g:
                            g.write(msg+'\n')
    record_ls.sort(reverse=True)

    return record_ls


class MyDirEventHandler(FileSystemEventHandler):

    def __init__(self,least_event):
        self.least_event = least_event

    def on_modified(self, event):
        # 这里路径是windows的安全事件日志路径
        if event.src_path == "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx":
            os.system(r"cd C:\Users\Administrator\Desktop")
            os.system(r"evtx_dump.exe C:\Windows\System32\winevt\Logs\Security.evtx"
                      r" --dont-show-record-number --no-confirm-overwrite -f save.xml")
            # 处理xml文件
            xml_handle('save.xml')
            write_tail(newxml)
            ls = lxml_handle(newxml, ip, self.least_event)
            if ls:
                self.least_event = ls[0]
                print(self.least_event)
                pass



# 获取IP

# 一旦发现文件改变，调用本地解释程序
if __name__ == "__main__":
    # 获取IP
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    #设定要读取的xml文件
    newxml = 'newxml.xml'
    # 获取最新的事件
    least_event = 0
    # 创建事件处理对象
    observer = Observer()
    fileHandler = MyDirEventHandler(least_event)
    # 为观察者设置观察对象与处理事件对象
    observer.schedule(fileHandler, r"C:\Windows\System32\winevt\Logs", True)
    observer.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

