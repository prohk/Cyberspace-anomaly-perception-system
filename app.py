from flask import Flask, make_response, jsonify, flash
from flask import render_template, request, session, redirect, url_for
import flask
from flask_sse import sse
import threading
import remote_read_log
from time import sleep
import pymysql
import json
import datetime
from datetime import timedelta
import readlog
# from gevent import monkey
# import gevent
# monkey.patch_all()
# 判断系统为win或linux系统
# WIN = sys.platform.startswith('win')
# if WIN:
#     prefix = 'sqlite:///'
# else:
#     prefix = 'sqlite:////'

# 实例化flask对象
app = Flask(__name__)
# 用作SSE通道缓存的redis数据库
app.config["SSE_REDIS_URL"] = "redis://127.0.0.1:6379/0"
app.register_blueprint(sse, url_prefix='/stream')  # 注册SSE的蓝图，并访问路由为/stream
app.secret_key = 'You Guess Guess !?'
# mysql配置
db = pymysql.connect(host="localhost", database="web", user="root", password="mysql", port=3386, charset="utf8")
print(db)

# 数据库模块
cursor = db.cursor()


# 远程命令执行模块
@app.route('/run')
def run_cmd():
    threads = []
    cmd = 'tail -f -n -1 /var/log/auth.log'
    cmd_login_win = 'powershell get-content -path C:/logfile/ids-event.txt -wait -tail 1 -Encoding utf8'
    sensive_dir = '/etc/resolv.conf /etc/passwd /etc/shadow /etc/httpd/httpd.conf'  # 敏感目录
    cmd_mondir = "inotifywait -mrq --timefmt '%d/%m/%y %H:%M' --format '%T %w %f %e' -e modify /etc/passwd " \
                 "/etc/shadow /var/spool/cron/crontabs /proc/version /usr/share/iptables /etc/group /etc/hosts.allow /etc/hosts.deny " \
                 "/etc/ssh/sshd_config "
    cmd_monusage = "powershell -nop -c \"iex(New-Object Net.WebClient).DownloadString(" \
                   "'youip') "
    cmd_linux_monusage = "cd /root/temptool && ./linux_mon.sh "
    cmd_toids = '''powershell get-content -path C:/logfile/ids-event.txt -wait -tail 1 -Encoding utf8'''
    cmd_tovirus = '''powershell get-content -path C:/logfile/virus-event.txt -wait -tail 1 -Encoding utf8'''
    # linux监视资源线程
    th_linux_monusage = threading.Thread(
            target=flask.copy_current_request_context(remote_read_log.link_server_client),
            args=('xxx.xxx.xxx.xxx', 'admin', 'admin', cmd_linux_monusage, 'monlinux_usage'))
    # IP ，SSH用户名密码
    threads.append(th_linux_monusage)
    # windows监视资源线程
    th_windows_monusage = threading.Thread(
        target=flask.copy_current_request_context(remote_read_log.link_server_client),
        args=('xxx.xxx.xxx.xxx', 'admin', 'admin', cmd_monusage, 'monwin_usage'))
    threads.append(th_windows_monusage)
    # linux登陆日志采集线程
    th = threading.Thread(
        target=flask.copy_current_request_context(remote_read_log.link_server_client),
        args=('xxx.xxx.xxx.xxx', 'admin', 'admin', cmd, 'auth'),
        name='linux_auth')
    threads.append(th)
    # linux敏感目录线程
    th3 = threading.Thread(
        target=flask.copy_current_request_context(remote_read_log.link_server_client),
        args=('xxx.xxx.xxx.xxx', 'admin', 'admin', cmd_mondir, 'mondir'),
        name='linux_mondir')
    threads.append(th3)
    # windows 登陆日志采集线程
    th_winlogin = threading.Thread(
        target=flask.copy_current_request_context(remote_read_log.link_server_client),
        args=('xxx.xxx.xxx.xxx', 'admin', 'admin', cmd_login_win, 'login'),
        name='linux_mondir')
    threads.append(th_winlogin)
    #IDS、virus
    key = ['virus', 'ids']
    # ls_viruslog = [1, 3, 4, 4, 4, 4]
    # ls_idslog = [2, 3, 4, 4, 6]
    # 这里填本地或远程的地址
    ids_log = "C:/Users/J/Desktop/毕设系统/ids-event.txt"
    virus_log = "C:/Users/J/Desktop/毕设系统/virus-event.txt"
    cataline = r"C:\Users\J\Desktop\毕设系统\catalina.2020-05-04.log"
    th4 = threading.Thread(
        target=flask.copy_current_request_context(readlog.follow_log),
        args=(ids_log,'ids')
    )
    threads.append(th4)
    th5 = threading.Thread(
        target=flask.copy_current_request_context(readlog.follow_log),
        args=(virus_log, 'virus')
    )
    threads.append(th5)
    # th4 = threading.Thread(
    #     target=flask.copy_current_request_context(readlog.follow_log),
    #     args=(cataline,'business')
    # )
    threads.append(th4)
    for i in range(len(threads)):
        threads[i].start()
    return "success connect"


# 接受网页中接口的数据，并通过sse实时推送给用户
def push_log(message, channel):
    if channel != 'analysis':
        sse.publish({"message": message}, type='social', channel=channel)
        print('%s 发送成功！' % message)
        analysis(message)
    elif channel == 'analysis':
        sse.publish({"message": message}, type='social', channel=channel)
        print('%s 发送成功！' % message)
    else:
        print('发送消息失败')

def analysis(message):
    ip_re = ".*?(\d{2,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}).*"
    now_time = datetime.datetime.now()
    msg = message
    ip = remote_read_log.re_handle(ip_re, msg)
    print(msg)
    if '内存' in msg or 'cpu' in msg:
        key = '资源使用异常'
    elif '登陆' in msg:
        key = '登陆行为异常'
    elif '关键配置' in msg:
        key = '敏感目录异常'
    elif '感染' in msg:
        key = '病毒感染'
        words = r"type='内存异常' or type='cpu异常'"
        result = db_query_todaylog(ip,words)
        if result:
            new_msg = "%s高危:关联分析探测到主机%s同时出现病毒感染和系统异常，系统大概率已沦陷！"%(now_time,ip)
            push_log(new_msg,'analysis')
        words = r"type='漏洞攻击' or type='探测行为'"
        result = db_query_todaylog(ip, words)
        if result:
            new_msg = "%s关联分析探测到主机%s同时出现病毒感染和漏洞攻击/探测行为，该系统大概率已沦陷！" % (now_time, ip)
            push_log(new_msg, 'analysis')
    elif '漏洞' in msg:
        key = '漏洞攻击/探测行为'
        ip_re = ".*\s(\d{2,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3})\s.*"
        srcip = remote_read_log.re_handle(ip_re,msg)
        words = r"type='破解行为'"
        result = db_query_todaylog(srcip, words)
        print(srcip)
        if result:
            new_msg = "%s高危:关联分析探测到主机%s同时出现漏洞攻击/探测和破解行为，该系统大概率已沦陷！" % (now_time, srcip)
            push_log(new_msg, 'analysis')
    else:
        print('无法获取到关联分析的key！')



def db_query_todaylog(ip,words):
    try:
        sql = r"select type from 所有告警日志 where serverip='%s' and %s"%(ip,words)
        affect_row = cursor.execute(sql)
        if affect_row >0:
            print('查询到关联日志！')
            return True
        else:
            print('未能查询到关联日志！')
            return False
    except Exception as e:
        print(e)
        print('查询所有告警日志失败')


def db_insert(tables, data):
    try:
        sql_cmd = '''insert into %s(serverip,time,msg,type) values(%s);''' % (tables, data)
        print(sql_cmd)
        cursor.execute(sql_cmd)
        db.commit()
        print("成功插入一条数据")
    except Exception as e:
        print("数据插入错误")
        print(e)




def db_insert_user(tables, data):
    try:
        sql_cmd = '''insert into %s(user,password,role) values%s;''' % (tables, data)
        print(sql_cmd)
        cursor.execute(sql_cmd)
        db.commit()
        print("成功添加用户")
        return True
    except Exception as e:
        print(e)
        print("添加用户错误")
        return False



def db_update(tables, data, serverip, time, msg):
    try:
        sql_cmd = cursor.execute(
            "update %s set type=%s where serverip=%s and time=%s and msg=%s;" % (tables, data, serverip, time, msg))
        cursor.execute(sql_cmd)
        db.commit()
        print("成功插入一条数据")
        return True
    except Exception as e:
        print("数据插入错误")
        print(e)
    # type 格式 '10' 破解行为的格式为 int 10


def db_update_user(username,password,role):
    try:
        sql_cmd = '''update users set password='%s',role='%s' where user='%s' '''%(password,role,username)
        cursor.execute(sql_cmd)
        db.commit()
        print("成功更改用户密码")
        return True
    except Exception as e:
        print("更改密码错误")
        print(e)
        return False




# 测试模块
# 配置flask shell 数据库初始化命令
# @app.cli.command()  # 注册为命令
# @click.option('--drop', is_flag=True, help='Create after drop')  # 设置选项
# def initdb(drop):
#     if drop:
#         db.drop_all()
#     db.create_all()
#     click.echo('Initialized database')


# 主体部分
@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # 查看当前用户是否登陆
        if not session.get("username"):
            return redirect(url_for('login'), 302)
        if 'username' in session:
            print("用户连接成功，session为：%s" % session['username'])
            # 管理员添加任务
            host = request.args.get('host')
            if host:
                username = request.args.get('username')
                password = request.args.get('password')
                command = request.args.get('command')
                link_server = flask.copy_current_request_context(remote_read_log.link_server_client)
                if host and username and password and command is not None:
                    index_threads = []
                    index_th = threading.Thread(target=link_server,
                                                args=(host, username, password, command, 'custom'))
                    index_threads.append(index_th)
                    for i in range(len(index_threads)):
                        index_threads[i].start()
                    for i in range(len(index_threads)):
                        index_threads[i].join()
            else:
                return render_template('index.html', name=session['username'])
    else:
        if 'username' in session:
            return render_template('index.html', name=session['username'])


@app.route('/login', methods=["GET", "POST"])
@app.route('/login.html', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if db_query_users('users',username):
            user_pass = db_query_password('users',username)
            # if username == 'admin' and password == '123456':
            if password == user_pass:
                session['username'] = username
                # session['password'] = password
                app.permanent_session_lifetime = timedelta(minutes=10)
                resp = make_response(render_template('index.html', name=username))
                resp.set_cookie('username', username)
                push_log(session['username'], channel='html')
                sleep(1.0)
                return jsonify({'status': '0', 'errmsg': '认证成功！'})
            else:
                return jsonify({'status': '-1', 'errmsg': '用户名或密码错误！'})

        else:
            return jsonify({'status': '-1', 'errmsg': '用户名或密码错误！'})
    return render_template('login.html')


@app.route('/logout',methods=['GET','POST'])
def log_out():
    session.clear()
    return redirect(url_for('login'))


def db_query_password(tables,user):
    try:
        row = cursor.execute("select password from %s where user='%s';" %(tables,user))
        result = cursor.fetchall()
        return result[0][0]
    except Exception as e:
        print(e)
        print("查询错误")


@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    crack_row = db_count('破解行为')
    virus_row = db_count('防病毒系统日志')
    ids_row = db_count('ids')
    windows_row = db_count('windows_log')
    linux_row = db_count('linux_log')
    business_row = db_count('业务系统异常')
    server_row = windows_row + linux_row
    # 生成一个json数据
    temp_dict = {}
    temp_xls = ['crack_row', 'business_row', 'server_row', 'ids_row', 'virus_row']
    temp_yls = [crack_row, business_row, server_row, ids_row, virus_row]
    temp_dict['name'] = temp_xls
    temp_dict['data'] = temp_yls
    print(temp_dict)
    with open('report.json', 'w')as f:
        json.dump(temp_dict, f)
    return render_template('dashboard.html', crack_row=crack_row, virus_row=virus_row,
                           ids_row=ids_row, business_row=business_row, server_row=server_row
                           ,session=session['username']
                           )


@app.route('/dashboard/manage', methods=['GET', 'POST'])
def user_manage():
    if request.method == 'GET':
        users = []
        result = db_query('users')
        id = 0
        print(result)
        # 显示用户在线情况
        for row in result:
            users_dict = {}
            # 字典必须放在for 里，放外面只会造成同一内存的不断赋值
            id = id + 1
            users_dict['id'] = id
            users_dict['username'] = row[0]
            users_dict['password'] = '系统运维部'
            users_dict['role'] = row[2]
            if row[0] in session['username']:
                users_dict['status'] = '在线'
            else:
                users_dict['status'] = '离线'
            users.append(users_dict)
        return render_template('manage.html', users=users, manage=session['username'])


@app.route('/dashboard/manage/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        add_username = request.form['username']
        add_password = request.form['password']
        is_exist = db_query_users('users',add_username)
        if is_exist == True:
            return jsonify({'status':'2'})
        elif is_exist == False:
            role = 'observer'
            affect_row = db_insert_user('users', (add_username, add_password, role))
            if affect_row:
                return jsonify({'status': '0'})
            else:
                return jsonify({'status': '1'})


@app.route('/dashboard/manage/change_user',methods=['GET','POST'])
def change_user():
    if request.method == 'POST':
        change_username = request.form['username']
        change_password = request.form['password']
        role = 'observer'
        is_exist = db_query_users('users', change_username)
        if is_exist:
            result_update = db_update_user(change_username,change_password,role)
            if result_update:
                return jsonify({'status':'0'})
            else:
                return jsonify({'status':'1'})
        else:
            return jsonify({'status':'2'})

@app.route('/dashboard/manage/del_user',methods=['GET','POST'])
def del_user():
    if request.method == 'POST':
        del_username = request.form['username']
        admin_password = request.form['password']
        is_exist = db_query_users('users',del_username)
        if is_exist:
            query_password = db_query_password('users','admin')
            print(query_password)
            if admin_password == query_password:
                result = db_del('users',del_username)
                if result:
                    return jsonify({'status':'0'})
            else:
                return jsonify({'status':'1'})
        else:
            return jsonify({'status':'2'})


def db_count(tables):
    try:
        row_count = cursor.execute("select * from %s;" % tables)
        return row_count
    except Exception:
        print("查询错误")
    db.commit()
    return


def db_query(tables):
    try:
        cursor.execute("select * from %s;" % tables)
        db.commit()
        result = cursor.fetchall()
        return result
    except Exception as e:
        print("查询错误")
        print(e)


def db_query_users(tables,user):
    try:
        sql_cmd = '''select * from %s where user ='%s';''' % (tables,user)
        cursor.execute(sql_cmd)
        result = cursor.fetchall()
        db.commit()
        if result:
            return True
        else:
            return False
    except Exception as e:
        print(e)
        print('查询错误')
        return False




def db_del(tables,key):
    try:
        cmd_sql = '''delete from %s where user = '%s';'''%(tables,key)
        cursor.execute(cmd_sql)
        db.commit()
        print('删除用户成功')
        return True
    except Exception as e:
        print(e)
        print('查询错误')
        return False


@app.route('/getsession', methods=["GET", "POST"])
def get_session():
    user_session = session['username']
    print(user_session)
    return user_session


@app.route('/report', methods=["GET", "POST"])
def get_json():
    with open('report.json', 'r')as f:
        json_str = json.load(f)
        return jsonify(json_str)


# @app.before_request
# def check():
#     if (not session.get('username') and not request.path.startswith('/static')
#             and request.path != '/login'
#             and request.path == '/'
#             and not request.path.startswith('/run')
#             and not request.path.startswith('/stream')):
#         return redirect(url_for('login'))


@app.errorhandler(404)
def error(error_no):
    return "您访问的路径不存在"


if __name__ == '__main__':
    # gevent.spawn(app.run, args=())
    app.run(threaded=True, debug=True)
