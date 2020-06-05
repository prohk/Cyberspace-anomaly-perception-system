from app import app, db
from module.models import login_msg


@app.shell_context_processor  # 将该函数注册为flask shell上下文函数，不用辛苦先导包了
def make_shell_context():
    return {'db': db, 'login_msg': login_msg}
