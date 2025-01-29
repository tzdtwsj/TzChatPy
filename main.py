# 基于Python的网页聊天室
# By tzdtwsj.

from flask import Flask, request, jsonify, redirect, make_response
from flask_socketio import SocketIO, join_room, emit
import os
import json
import hashlib
import time
import re
from threading import Lock

app = Flask(__name__)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = 'secret!'

user_data_lock = Lock()
history_data_lock = Lock()
room_data_lock = Lock()

config = {}

from sendmail import sendmail


verify_data = []
"""{
   'username': str,
   'password': str,
   'email': str,
   'code': str,
}
"""

online_users = {}
"""{
    room_id1: {
        username1: [session_id1, session_id2, ...],
        username2: [session_id1, session_id2, ...],
        ...
    },
    room_id2: {
        username1: [session_id1, session_id2, ...],
        username2: [session_id1, session_id2, ...],
        ...
    },
    ...
    }
}"""



def register_user(username, password, email):
    """注册用户"""
    """用户数据格式：{
    'username': str,
    'password': str,
    'email': str,
    'nickname': str,
    # permissions: 0为普通用户，1为管理员
    'permission': int,
    }
    """
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if user['username'] == username or user['email'] == email:
            return False
    if len(users) == 0:
        permission = 1
    else:
        permission = 0
    users.append({'username': username, 'password': md5(password), 'email': email, 'nickname': username, 'permission': permission})
    user_data_lock.acquire()
    with open('data/users.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(users, indent=4))
    user_data_lock.release()
    return True

def md5(data:str):
    """md5加密"""
    m = hashlib.md5()
    m.update(data.encode('utf-8'))
    return m.hexdigest()

def verify_user_from_token(token):
    """验证用户"""
    # token格式：md5("TzChatPy"+username+password)
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if md5("TzChatPy"+user['username']+user['password']) == token:
            return True
    return False

def get_user_from_token(token:str)->dict|bool:
    """获取用户"""
    # token格式：md5("TzChatPy"+username+password)
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if md5("TzChatPy"+user['username']+user['password']) == token:
            return user
    return False

def get_user_from_name(username):
    """获取用户"""
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if user['username'] == username:
            return user
    return False

def set_nickname(username, nickname):
    """设置用户昵称"""
    if type(nickname) != str:
        return False
    nickname = nickname.strip()
    if len(nickname) > 100 or len(nickname) < 1:
        return False
    if nickname == '':
        return False
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    users_new = []
    status = False
    for user in users:
        if user['username'] == username:
            user['nickname'] = nickname
            status = True
        users_new.append(user)
    if status == False:
        return False
    user_data_lock.acquire()
    with open('data/users.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(users_new, indent=4))
    user_data_lock.release()
    return True

def history_append(room_id,data):
    """追加历史记录"""
    with open('data/history.json', 'r', encoding='utf-8') as f:
        history = json.loads(f.read())
    if history.get(room_id) == None:
        history[room_id] = []
    history[room_id].append(data)
    history_data_lock.acquire()
    with open('data/history.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(history, indent=4))
    history_data_lock.release()
    return True

def history_get(room_id:str,count:int=0):
    """获取历史记录"""
    history_data_lock.acquire()
    with open('data/history.json', 'r', encoding='utf-8') as f:
        history = json.loads(f.read())
    history_data_lock.release()
    if history.get(room_id) == None:
        return []
    history_new = []
    for data in history[room_id][-count:]:
        history_new.append({
            'user': data.get('user'),
            'nickname': get_user_from_name(data.get('user')).get('nickname'),
            'message': data.get('message'),
            'msg_id': data.get('msg_id'),
            'time': data.get('time'),
            'recalled': data.get('recalled', False),
            'recaller': data.get('recaller'),
            'recaller_nickname': get_user_from_name(data.get('recaller')).get('nickname') if data.get('recaller') else None
        })
        if data.get('recalled'):
            history_new[-1]['message'] = ''
    return history_new


"""settings = {
    'nickname': str
}"""

def get_settings(username):
    """获取用户设置"""
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    settings = {}
    for user in users:
        if user['username'] == username:
            settings['nickname'] = user['nickname']
            return settings
    return False

def set_settings(username, settings):
    """设置用户设置"""
    users = get_user_from_name(username)
    if users == False:
        return False
    status = True
    if settings.get('nickname'):
        if set_nickname(username, settings.get('nickname')) == False:
            status = False
    return status

def recall_message(room_id, recaller, message_id):
    """撤回消息，直接标记历史消息为撤回，即recalled = True"""
    if get_user_from_name(recaller) == False: # 用户不存在
        return False
    if get_room_from_id(room_id) == False: # 房间不存在
        return False
    history_data_lock.acquire()
    with open('data/history.json', 'r', encoding='utf-8') as f:
        history = json.loads(f.read())
    history_data_lock.release()
    if history.get(room_id) == None:
        return False
    history_new = []
    status = False
    username = ''
    for data in history[room_id]:
        if data.get('msg_id') == message_id and (data.get('user') == recaller or get_user_from_name(recaller).get('permission') == 1 or get_room_from_id(room_id).get('creator') == recaller):
            if data.get('recalled') == True:
                return True
            data['recalled'] = True
            data['recaller'] = recaller
            username = data.get('user')
            status = True
        history_new.append(data)
    if status == False: # 没有找到消息
        return False
    history[room_id] = history_new
    history_data_lock.acquire()
    with open('data/history.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(history, indent=4))
    history_data_lock.release()
    emit('notice', {'type': 'recall_message', 'user': username, 'nickname':get_user_from_name(username).get('nickname'),'msg_id': message_id, 'recaller':recaller, 'recaller_nickname': get_user_from_name(recaller).get('nickname')}, to=room_id, namespace="/", broadcast=True)
    return True

def get_online_users(room_id):
    """获取在线用户"""
    if room_id not in online_users:
        return []
    return list(online_users[room_id].keys())

def get_rooms():
    """获取房间列表"""
    room_data_lock.acquire()
    with open('data/rooms.json', 'r', encoding='utf-8') as f:
        rooms = json.loads(f.read())
    room_data_lock.release()
    return rooms

def create_room(creator:str, room_name:str, room_description:str="No description"):
    """创建房间"""
    """{
        'room_name': str,
        'room_id': str,
    }"""
    rooms = get_rooms()
    for room in rooms:
        if room['room_name'] == room_name:
            return False
    room_id = md5(room_name+str(time.time()))[:16]
    room_data_lock.acquire()
    with open('data/rooms.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(rooms+[{
            'room_name': room_name,
            'room_description': room_description,
            'room_id': room_id,
            'creator': creator,
        }], indent=4))
    room_data_lock.release()
    return True

def get_room_from_id(room_id):
    """获取房间信息"""
    rooms = get_rooms()
    for room in rooms:
        if room['room_id'] == room_id:
            return room
    return False

def delete_room(creator:str, room_id:str):
    """删除房间"""
    rooms = get_rooms()
    status = False
    for room in rooms:
        if room['room_id'] == room_id:
            if room['creator'] != creator and get_user_from_name(creator).get('permission') != 1:
                return False
            rooms.remove(room)
            status = True
            break
    if status == False:
        return False
    room_data_lock.acquire()
    with open('data/rooms.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(rooms, indent=4))
    room_data_lock.release()
    history_data_lock.acquire()
    with open('data/history.json', 'r', encoding='utf-8') as f:
        history = json.loads(f.read())
    history_data_lock.release()
    if history.get(room_id) != None:
        history_data_lock.acquire()
        with open('data/history.json', 'w', encoding='utf-8') as f:
            del history[room_id]
            f.write(json.dumps(history, indent=4))
        history_data_lock.release()
    return True







# 当服务器发生错误时
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'status': 500, 'message': '未捕获的错误，请检查服务器日志'}), 500

@app.route('/')
def web_index_html():
    """返回当前目录index.html文件的内容"""
    with open('room.html', 'r', encoding='utf-8') as f:
        return f.read(), 200
    
@app.route('/login')
def web_login_html():
    """返回当前目录login.html文件的内容"""
    with open('login.html', 'r', encoding='utf-8') as f:
        return f.read(), 200
    
@app.route('/register')
def web_register_html():
    """返回当前目录register.html文件的内容"""
    with open('register.html', 'r', encoding='utf-8') as f:
        return f.read(), 200
    
@app.route('/settings')
def web_settings_html():
    """返回当前目录settings.html文件的内容"""
    with open('settings.html', 'r', encoding='utf-8') as f:
        return f.read(), 200

@app.route('/room')
def web_room_html():
    """返回当前目录room.html文件的内容"""
    with open('room.html', 'r', encoding='utf-8') as f:
        return f.read(), 200
    
@app.route('/room/<room_id>')
def web_room_html_room_id(room_id):
    """返回当前目录room.html文件的内容"""
    with open('chat.html', 'r', encoding='utf-8') as f:
        return f.read(), 200

@app.route('/register_user',methods=['POST'])
def web_register_user():
    """注册用户"""
    post_data = request.get_json()
    username = post_data.get('username')
    password = post_data.get('password')
    email = post_data.get('email')
    if not (type(username) == str and type(password) == str and type(email) == str):
        return '参数类型错误'
    # 先用正则检测用户名是否为数字加字母和下划线，减号的组合，并且长度大于等于3，小于等于16
    pattern = r'^[a-zA-Z0-9_-]{3,16}$'
    if not re.match(pattern, username):
        return jsonify({'status': 400, 'message': '用户名不符合要求'}), 400
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if user['username'] == username or user['email'] == email:
            return jsonify({'status': 400, 'message': '用户名或邮箱已存在'}), 400
    # 注册的同时登录，即向客户端发送token
    # return jsonify({'status': 200, 'message': '注册成功', 'token': md5("TzChatPy"+username+md5(password))}), 200
    # 发送邮件
    code = md5(username+password+email+str(time.time()))
    verify_data.append({'username': username, 'password': password, 'email': email, 'code': code, 'expire': time.time()+86400})
    link = 'http://'+request.host+'/verify_user?code='+code
    mail_sender = 'TzChatPy <'+config['mail_user']+'>'
    sendmail(config['mail_user'], config['mail_password'], mail_sender, email, '验证TzChatPy账户', '你好！<br>感谢你注册TzChatPy，访问该链接以完成注册：'+link+"<br>该链接在24小时内有效<br>如果这不是你发起的注册请求，请忽略此邮件。",config['mail_use_tls'])
    return jsonify({'status': 200, 'message': '我们已经向你的邮箱发送了验证邮件，请查收并点击链接以完成注册'}), 200

@app.route('/verify_user')
def web_verify_user():
    """验证用户"""
    global verify_data
    # 从url获取参数
    # http://xxx/verify_user?code=xxx
    code = request.args.get('code')
    if code == None:
        return jsonify({'status': 400, 'message': '缺少参数'}), 400
    status = False
    for data in verify_data:
        if data['code'] == code and data['expire'] > time.time():
            username = data['username']
            password = data['password']
            email = data['email']
            status = True
            break
    if status == False:
        return jsonify({'status': 400, 'message': '验证失败，请检查链接是否正确或已过期'}), 400
    verify_data_new = []
    for i in verify_data:
        if i['code'] != code and i['expire'] > time.time():
            verify_data_new.append(i)
    verify_data = verify_data_new
    if register_user(username, password, email) == False:
        return jsonify({'status': 400, 'message': '用户名或邮箱已存在'}), 400
    # 验证成功时设置浏览器的cookie，并302重定向到/
    response = make_response(redirect('/'))
    response.set_cookie('token', md5("TzChatPy"+username+md5(password)))
    return response

@app.route('/login_user',methods=['POST'])
def web_login_user():
    """登录用户"""
    post_data = request.get_json()
    username = post_data.get('username')
    password = post_data.get('password') # 该password需要被md5加密
    if not (type(username) == str and type(password) == str):
        return '参数类型错误'
    user_data_lock.acquire()
    with open('data/users.json', 'r', encoding='utf-8') as f:
        users = json.loads(f.read())
    user_data_lock.release()
    for user in users:
        if (user['username'] == username or user['email'] == username) and user['password'] == password:
            return jsonify({'status': 200, 'message': '登录成功', 'token': md5("TzChatPy"+user['username']+user['password'])}), 200
    return jsonify({'status': 403, 'message': '用户名或密码错误'}), 403

@app.route('/get_user',methods=['POST'])
def web_get_user():
    """获取用户信息"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    username = post_data.get('username')
    if type(username) != str:    
        user_data = {
            'username': get_user_from_token(token).get('username'),
            'email': get_user_from_token(token).get('email'),
            'nickname': get_user_from_token(token).get('nickname'),
        }
    else:
        user_data = {
            'username': username,
            'email': get_user_from_name(username).get('email'),
            'nickname': get_user_from_name(username).get('nickname'),
        }
    return jsonify({'status': 200, 'message': '成功', 'user': user_data}), 200

@app.route('/set_nickname',methods=['POST'])
def web_set_nickname():
    """设置用户昵称"""
    post_data = request.get_json()
    token = post_data.get('token')
    nickname = post_data.get('nickname')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    if type(nickname) != str:
        return jsonify({'status': 400, 'message': '昵称数据类型错误'}), 400
    if set_nickname(get_user_from_token(token).get('username'), nickname) == False:
        return jsonify({'status': 400, 'message': '用户名不存在（出现了bug?）'}), 400
    return jsonify({'status': 200, 'message': '设置成功'}), 200

@app.route('/get_history',methods=['POST'])
def web_get_history():
    """获取历史消息"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    count = post_data.get('count')
    if type(count) != int:
        count = 0
    room_id = post_data.get('room_id')
    if type(room_id) != str:
        return jsonify({'status': 400, 'message': '房间ID数据类型错误'}), 400
    if get_room_from_id(room_id) == False:
        return jsonify({'status': 400, 'message': '房间ID不存在'}), 400
    return jsonify({'status': 200, 'message': '成功', 'history': history_get(room_id,count)}), 200

@app.route('/get_settings',methods=['POST'])
def web_get_settings():
    """获取设置"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    return jsonify({'status': 200, 'message': '成功', 'settings': get_settings(get_user_from_token(token).get('username'))}), 200

@app.route('/set_settings',methods=['POST'])
def web_set_settings():
    """设置设置"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    settings = post_data.get('settings')
    if type(settings) != dict:
        return jsonify({'status': 400, 'message': '设置数据类型错误'}), 400
    if set_settings(get_user_from_token(token).get('username'), settings) == False:
        return jsonify({'status': 400, 'message': '用户名不存在（出现了bug?）'}), 400
    return jsonify({'status': 200, 'message': '设置成功'}), 200

@app.route('/recall_message',methods=['POST'])
def web_recall_message():
    """撤回消息"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    msg_id = post_data.get('msg_id')
    if type(msg_id) != str:
        return jsonify({'status': 400, 'message': '消息ID数据类型错误'}), 400
    room_id = post_data.get('room_id')
    if type(room_id) != str:
        return jsonify({'status': 400, 'message': '房间ID数据类型错误'}), 400
    if get_room_from_id(room_id) == False:
        return jsonify({'status': 400, 'message': '房间ID不存在'}), 400
    if recall_message(room_id, get_user_from_token(token).get('username'), msg_id) == False:
        return jsonify({'status': 400, 'message': '消息不存在或没权限撤回'}), 400
    return jsonify({'status': 200, 'message': '撤回成功'}), 200

@app.route('/get_online_users',methods=['POST'])
def web_get_online_users():
    """获取在线用户"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    room_id = post_data.get('room_id')
    if type(room_id) != str:
        return jsonify({'status': 400, 'message': '房间ID数据类型错误'}), 400
    if get_room_from_id(room_id) == False:
        return jsonify({'status': 400, 'message': '房间ID不存在'}), 400
    return jsonify({'status': 200, 'message': '成功', 'online_users': get_online_users(room_id)}), 200

@app.route('/create_room',methods=['POST'])
def web_create_room():
    """创建房间"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    room_name = post_data.get('room_name')
    if type(room_name) != str:
        return jsonify({'status': 400, 'message': '参数数据类型错误'}), 400
    if room_name == '':
        return jsonify({'status': 400, 'message': '参数不能为空'}), 400
    # if get_user_from_token(token).get('permission') != 1:
    #     return jsonify({'status': 403, 'message': '权限不足'}), 403
    if create_room(get_user_from_token(token).get('username'),room_name) == False:
        return jsonify({'status': 400, 'message': '房间名已存在'}), 400
    return jsonify({'status': 200, 'message': '创建成功'}), 200

@app.route('/delete_room',methods=['POST'])
def web_delete_room():
    """删除房间"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    room_id = post_data.get('room_id')
    if type(room_id) != str:
        return jsonify({'status': 400, 'message': '参数数据类型错误'}), 400
    if room_id == '':
        return jsonify({'status': 400, 'message': '参数不能为空'}), 400
    # if get_user_from_token(token).get('permission') != 1:
    #     return jsonify({'status': 403, 'message': '权限不足'}), 403
    if delete_room(get_user_from_token(token).get('username'),room_id) == False:
        return jsonify({'status': 400, 'message': '房间不存在或没权限删除房间'}), 400
    return jsonify({'status': 200, 'message': '删除成功'}), 200

@app.route('/get_rooms',methods=['POST'])
def web_get_rooms():
    """获取房间列表"""
    post_data = request.get_json()
    token = post_data.get('token')
    if verify_user_from_token(token) == False:
        return jsonify({'status': 403, 'message': '验证失败'}), 403
    return jsonify({'status': 200, 'message': '成功', 'rooms': get_rooms()}), 200

        




@socketio.on('connect') # 当客户端连接时触发
def handle_connect():
    pass

@socketio.on('disconnect') # 当客户端断开连接时触发
def handle_disconnect():
    global online_users
    status = False
    for room_id in online_users:
        for username in online_users[room_id]:
            if request.sid in online_users[room_id][username]:
                online_users[room_id][username].remove(request.sid)
                if len(online_users[room_id][username]) == 0:
                    del online_users[room_id][username]
                    if len(online_users[room_id]) == 0:
                        del online_users[room_id]
                    emit('notice', {'type': 'user_disconnect', 'username': username}, to=room_id, broadcast=True)
                status = True
                break
        if status:
            break

@socketio.on('verify_user') # 当客户端发送验证请求时触发
def handle_verify_user(data):
    """验证用户，然后把用户加入对应的房间ID以接收消息"""
    """data: dict {token: str, room_id: str}"""
    token = data.get('token')
    if token == None:
        emit('verify_user', {'status': 400, 'message': 'token不能为空'})
    if verify_user_from_token(token) == False:
        emit('verify_user', {'status': 403, 'message': '验证失败'})
        return
    room_id = data.get('room_id')
    if room_id == '':
        emit('verify_user', {'status': 400, 'message': '房间ID不能为空'})
        return
    if type(room_id) != str:
        emit('verify_user', {'status': 400, 'message': '房间ID类型错误'})
        return
    join_room(room_id)
    emit('verify_user', {'status': 200, 'message': '验证成功'}, to=room_id)
    sid = request.sid
    global online_users
    if online_users.get(room_id) == None:
        online_users[room_id] = {}
    if online_users[room_id].get(get_user_from_token(token).get('username')) == None:
        online_users[room_id][get_user_from_token(token).get('username')] = []
    online_users[room_id][get_user_from_token(token).get('username')].append(sid)
    if len(online_users[room_id][get_user_from_token(token).get('username')]) == 1:
        emit('notice', {'type': 'user_connect', 'username': get_user_from_token(token).get('username')}, to=room_id, broadcast=True, include_self=False)

@socketio.on('message') # 当客户端发送消息时触发
def handle_message(data):
    """发送消息"""
    # data: dict {token: str, message: str， room_id: str}
    if verify_user_from_token(data.get('token')) == False:
        emit('message', {'status': 403, 'message': '验证失败'})
        return
    if data.get('message') == '':
        emit('message', {'status': 400, 'message': '消息不能为空'})
        return
    message = data.get('message')
    if type(message) != str:
        emit('message', {'status': 400, 'message': '消息类型错误'})
        return
    room_id = data.get('room_id')
    if room_id == '':
        emit('message', {'status': 400, 'message': '房间ID不能为空'})
        return
    if type(room_id) != str:
        emit('message', {'status': 400, 'message': '房间ID类型错误'})
        return
    if get_room_from_id(room_id) == False:
        emit('message', {'status': 400, 'message': '房间不存在'})
        return
    message = message.replace('&', '&amp;').replace("\r\n","<br>").replace("\n","<br>").replace("\r","<br>")
    if config['enable_html'] == False:
        message = message.replace('<', '&lt;').replace('>', '&gt;')
    send_time = time.time()
    msg_id = md5(message+str(time.time()))[:16]
    msg_data = {
        'user': get_user_from_token(data.get('token')).get('username'),
        'message': message,
        'msg_id': msg_id,
        'time': send_time,
        'recalled': False,
    }
    history_append(room_id,msg_data)
    msg_data['nickname'] = get_user_from_token(data.get('token')).get('nickname')
    emit('message', msg_data, to=room_id, broadcast=True)

if __name__ == '__main__':
    if not os.path.isdir('data'):
        os.mkdir('data')
    if not os.path.isfile('data/users.json'):
        with open('data/users.json', 'w', encoding='utf-8') as f:
            f.write('[]')
    if not os.path.isfile('data/history.json'):
        with open('data/history.json', 'w', encoding='utf-8') as f:
            f.write(r'{}')
    if not os.path.isfile('data/rooms.json'):
        with open('data/rooms.json', 'w', encoding='utf-8') as f:
            f.write('[]')
    if not os.path.isfile('data/config.json'):
        with open('data/config.json', 'w', encoding='utf-8') as f:
            f.write(json.dumps({
                'listen_host': '0.0.0.0',
                'listen_port': 8080,
                'mail_host': '',
                'mail_port': 25,
                'mail_use_tls': False,
                'mail_user': '',
                'mail_password': '',
                'enable_html': False,
            }, ensure_ascii=False, indent=4))
    with open('data/config.json', 'r', encoding='utf-8') as f:
        config = json.loads(f.read())
    socketio.run(app, host=config['listen_host'], port=config['listen_port'], debug=False)