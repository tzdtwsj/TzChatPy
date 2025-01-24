# TzChatPy

## 这是什么
这是一个基于Flask和SocketIO的聊天室项目，使用Python编写。

## 如何使用
1. 安装依赖
```bash
pip install -r requirements.txt
```

2. 先启动一遍，生成配置文件
```bash
python3 main.py
```

3. 修改配置文件，配置smtp发件
```json
{
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "mail_host": "",
    "mail_port": 25,
    "mail_use_tls": false,
    "mail_user": "",
    "mail_password": "",
    "enable_html": false
}```

4. 重新启动
```bash
python3 main.py
```

5. 访问`http://localhost:8080`即可使用，注册的第一个用户即为管理员账户

## 已支持的功能
- 用户注册、登录、登出
- 用户修改昵称
- 用户撤回消息
- 多房间聊天
- 房间里显示在线人数

