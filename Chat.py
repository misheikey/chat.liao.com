import uuid
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json
from threading import Lock
import time
import hashlib

# 初始化应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 改进的消息队列 - 解决重复消息问题
class MessageQueue:
    def __init__(self):
        self.messages = {}
        self.message_hashes = {}
        self.lock = Lock()
        self.next_id = 0
    
    def add_message(self, user_id, message_data):
        """添加消息，确保同一条消息不会重复添加"""
        with self.lock:
            # 为消息创建唯一标识
            message_hash = self._create_message_hash(message_data)
            
            if user_id not in self.messages:
                self.messages[user_id] = []
                self.message_hashes[user_id] = set()
            
            # 检查是否已存在相同消息
            if message_hash not in self.message_hashes[user_id]:
                message = {
                    'id': self.next_id,
                    'data': message_data,
                    'timestamp': time.time(),
                    'hash': message_hash
                }
                self.messages[user_id].append(message)
                self.message_hashes[user_id].add(message_hash)
                self.next_id += 1
                return True
            return False
    
    def _create_message_hash(self, message_data):
        """创建消息的唯一哈希值"""
        content = json.dumps(message_data, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_messages(self, user_id, last_id=-1):
        """获取新消息"""
        with self.lock:
            if user_id not in self.messages:
                return []
            
            user_messages = self.messages[user_id]
            new_messages = [msg for msg in user_messages if msg['id'] > last_id]
            return new_messages
    
    def clear_old_messages(self, max_age=300):
        """清理过期消息（5分钟以上的消息）"""
        with self.lock:
            current_time = time.time()
            for user_id in list(self.messages.keys()):
                self.messages[user_id] = [
                    msg for msg in self.messages[user_id] 
                    if current_time - msg['timestamp'] < max_age
                ]
                # 同时清理message_hashes
                if user_id in self.message_hashes:
                    current_hashes = {msg['hash'] for msg in self.messages[user_id]}
                    self.message_hashes[user_id] = current_hashes

message_queue = MessageQueue()

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref='sent_requests')
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref='received_requests')

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='friendships')
    friend = db.relationship('User', foreign_keys=[friend_id])

class Group(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='created_groups')

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    group = db.relationship('Group', backref='members')
    user = db.relationship('User', backref='group_memberships')

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    from_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    group = db.relationship('Group', backref='messages')
    from_user = db.relationship('User', backref='group_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# 路由定义
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>社交平台</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 0; 
                padding: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .container { 
                max-width: 800px; 
                margin: 50px auto; 
                background: white; 
                padding: 40px; 
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                text-align: center;
            }
            .header { 
                margin-bottom: 30px; 
            }
            .header h1 { 
                color: #333; 
                margin-bottom: 10px;
                font-size: 2.5em;
            }
            .header p { 
                color: #666; 
                font-size: 1.2em;
            }
            .auth-buttons { 
                margin: 30px 0; 
            }
            .btn { 
                padding: 10px 20px; 
                margin: 5px; 
                text-decoration: none; 
                border-radius: 5px; 
                display: inline-block;
            }
            .btn-primary { 
                background: #007bff; 
                color: white; 
            }
            .btn-success { 
                background: #28a745; 
                color: white; 
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-top: 40px;
            }
            .feature {
                padding: 20px;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #007bff;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>欢迎来到社交平台</h1>
                <p>与朋友保持联系，创建群组聊天</p>
            </div>
            <div class="auth-buttons">
                <a href="/login" class="btn btn-primary">登录</a>
                <a href="/register" class="btn btn-success">注册</a>
            </div>
            <div class="features">
                <div class="feature">
                    <h3>安全注册</h3>
                    <p>使用UUID系统确保账户安全</p>
                </div>
                <div class="feature">
                    <h3>好友管理</h3>
                    <p>通过UUID添加和管理好友</p>
                </div>
                <div class="feature">
                    <h3>实时聊天</h3>
                    <p>与好友进行实时私聊</p>
                </div>
                <div class="feature">
                    <h3>群组功能</h3>
                    <p>创建和加入群组聊天</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>注册</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                    .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }
                    .form-group { margin-bottom: 15px; }
                    label { display: block; margin-bottom: 5px; }
                    input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                    .btn { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                    .error { color: red; margin-bottom: 15px; }
                    .login-link { text-align: center; margin-top: 15px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>注册新账户</h2>
                    <div class="error">密码不匹配</div>
                    <form method="POST">
                        <div class="form-group">
                            <label>用户名:</label>
                            <input type="text" name="username" value="''' + username + '''" required>
                        </div>
                        <div class="form-group">
                            <label>密码:</label>
                            <input type="password" name="password" required>
                        </div>
                        <div class="form-group">
                            <label>确认密码:</label>
                            <input type="password" name="confirm_password" required>
                        </div>
                        <button type="submit" class="btn">注册</button>
                    </form>
                    <div class="login-link">
                        <a href="/login">已有账户？立即登录</a>
                    </div>
                </div>
            </body>
            </html>
            ''')
        
        if User.query.filter_by(username=username).first():
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>注册</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                    .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }
                    .form-group { margin-bottom: 15px; }
                    label { display: block; margin-bottom: 5px; }
                    input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                    .btn { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                    .error { color: red; margin-bottom: 15px; }
                    .login-link { text-align: center; margin-top: 15px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>注册新账户</h2>
                    <div class="error">用户名已存在</div>
                    <form method="POST">
                        <div class="form-group">
                            <label>用户名:</label>
                            <input type="text" name="username" value="''' + username + '''" required>
                        </div>
                        <div class="form-group">
                            <label>密码:</label>
                            <input type="password" name="password" required>
                        </div>
                        <div class="form-group">
                            <label>确认密码:</label>
                            <input type="password" name="confirm_password" required>
                        </div>
                        <button type="submit" class="btn">注册</button>
                    </form>
                    <div class="login-link">
                        <a href="/login">已有账户？立即登录</a>
                    </div>
                </div>
            </body>
            </html>
            ''')
        
        new_user = User(
            username=username,
            password=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('dashboard'))
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>注册</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
            .btn { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .login-link { text-align: center; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>注册新账户</h2>
            <form method="POST">
                <div class="form-group">
                    <label>用户名:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>密码:</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>确认密码:</label>
                    <input type="password" name="confirm_password" required>
                </div>
                <button type="submit" class="btn">注册</button>
            </form>
            <div class="login-link">
                <a href="/login">已有账户？立即登录</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>登录</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }
                .form-group { margin-bottom: 15px; }
                label { display: block; margin-bottom: 5px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                .btn { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                .error { color: red; margin-bottom: 15px; }
                .register-link { text-align: center; margin-top: 15px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>登录</h2>
                <div class="error">无效的用户名或密码</div>
                <form method="POST">
                    <div class="form-group">
                        <label>用户名:</label>
                        <input type="text" name="username" value="''' + username + '''" required>
                    </div>
                    <div class="form-group">
                        <label>密码:</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">登录</button>
                </form>
                <div class="register-link">
                    <a href="/register">没有账户？立即注册</a>
                </div>
            </div>
        </body>
        </html>
        ''')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>登录</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
            .btn { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .register-link { text-align: center; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>登录</h2>
            <form method="POST">
                <div class="form-group">
                    <label>用户名:</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>密码:</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit" class="btn">登录</button>
            </form>
            <div class="register-link">
                <a href="/register">没有账户？立即注册</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # 获取好友列表
    friendships = Friendship.query.filter_by(user_id=current_user.id).all()
    friends = [friendship.friend for friendship in friendships]
    
    # 获取待处理的好友请求
    pending_requests = FriendRequest.query.filter_by(to_user_id=current_user.id, status='pending').all()
    
    # 获取群组列表
    user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
    groups = [member.group for member in user_groups]
    
    # 获取最近消息
    recent_messages = PrivateMessage.query.filter(
        (PrivateMessage.from_user_id == current_user.id) | 
        (PrivateMessage.to_user_id == current_user.id)
    ).order_by(PrivateMessage.timestamp.desc()).limit(5).all()
    
    friends_html = ''.join([f'''
        <div class="friend-item">
            <a href="/chat/{friend.id}" class="friend-link">
                <span class="friend-avatar">👤</span>
                <span class="friend-name">{friend.username}</span>
            </a>
            <span class="friend-uuid">({friend.id[:8]}...)</span>
        </div>
    ''' for friend in friends]) or '<div class="no-data">暂无好友</div>'
    
    requests_html = ''.join([f'''
        <div class="request-item">
            <div class="request-info">
                <strong>{request.from_user.username}</strong> 想添加你为好友
            </div>
            <div class="request-actions">
                <button class="btn btn-success accept-friend" data-request-id="{request.id}">接受</button>
                <button class="btn btn-danger reject-friend" data-request-id="{request.id}">拒绝</button>
            </div>
        </div>
    ''' for request in pending_requests]) or '<div class="no-data">暂无待处理请求</div>'
    
    groups_html = ''.join([f'''
        <div class="group-item">
            <a href="/group_chat/{group.id}" class="group-link">
                <strong>{group.name}</strong>
            </a>
            <span class="group-id">({group.id[:8]}...)</span>
        </div>
    ''' for group in groups]) or '<div class="no-data">暂无群组</div>'
    
    messages_html = ''.join([f'''
        <div class="message-item">
            <div class="message-sender">
                {"我" if message.from_user_id == current_user.id else message.from_user.username} → 
                {"我" if message.to_user_id == current_user.id else message.to_user.username}
            </div>
            <div class="message-content">{message.content[:30]}{"..." if len(message.content) > 30 else ""}</div>
        </div>
    ''' for message in recent_messages]) or '<div class="no-data">暂无消息</div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>社交平台 - 仪表板</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            
            .header {{
                background: white;
                padding: 30px;
                border-radius: 15px;
                margin-bottom: 20px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                text-align: center;
            }}
            
            .header h1 {{
                color: #333;
                margin-bottom: 10px;
                font-size: 2.5em;
            }}
            
            .uuid-display {{
                background: #f8f9fa;
                padding: 10px 15px;
                border-radius: 25px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                color: #666;
                margin: 15px 0;
                display: inline-block;
            }}
            
            .dashboard-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }}
            
            .card {{
                background: white;
                padding: 25px;
                border-radius: 15px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            
            .card h3 {{
                color: #333;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 2px solid #f0f0f0;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .form-group {{
                margin-bottom: 15px;
            }}
            
            input, textarea {{
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                transition: border-color 0.3s ease;
            }}
            
            input:focus, textarea:focus {{
                outline: none;
                border-color: #007bff;
            }}
            
            textarea {{
                min-height: 80px;
                resize: vertical;
            }}
            
            .btn {{
                padding: 10px 20px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-block;
                text-align: center;
            }}
            
            .btn-primary {{
                background: #007bff;
                color: white;
            }}
            
            .btn-primary:hover {{
                background: #0056b3;
                transform: translateY(-1px);
                box-shadow: 0 3px 10px rgba(0,123,255,0.3);
            }}
            
            .btn-success {{
                background: #28a745;
                color: white;
            }}
            
            .btn-success:hover {{
                background: #1e7e34;
                transform: translateY(-1px);
            }}
            
            .btn-danger {{
                background: #dc3545;
                color: white;
            }}
            
            .btn-danger:hover {{
                background: #c82333;
                transform: translateY(-1px);
            }}
            
            .friend-item, .request-item, .group-item, .message-item {{
                padding: 12px;
                margin: 8px 0;
                background: #f8f9fa;
                border-radius: 8px;
                border-left: 4px solid #007bff;
            }}
            
            .friend-link, .group-link {{
                text-decoration: none;
                color: #333;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .friend-avatar {{
                font-size: 1.2em;
            }}
            
            .friend-uuid, .group-id {{
                font-size: 0.8em;
                color: #666;
                font-family: 'Courier New', monospace;
            }}
            
            .request-item {{
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .request-actions {{
                display: flex;
                gap: 5px;
            }}
            
            .request-actions .btn {{
                padding: 5px 10px;
                font-size: 12px;
            }}
            
            .no-data {{
                text-align: center;
                color: #666;
                font-style: italic;
                padding: 20px;
            }}
            
            .message-sender {{
                font-weight: 600;
                color: #333;
                margin-bottom: 5px;
            }}
            
            .message-content {{
                color: #666;
                font-size: 0.9em;
            }}
            
            @media (max-width: 768px) {{
                .dashboard-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .header h1 {{
                    font-size: 2em;
                }}
                
                .request-item {{
                    flex-direction: column;
                    gap: 10px;
                }}
                
                .request-actions {{
                    width: 100%;
                    justify-content: center;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <!-- 头部信息 -->
            <div class="header">
                <h1>🎉 欢迎回来, {current_user.username}!</h1>
                <div class="uuid-display">你的唯一标识: {current_user.id}</div>
                <a href="/logout" class="btn btn-danger">退出登录</a>
            </div>
            
            <div class="dashboard-grid">
                <!-- 好友管理卡片 -->
                <div class="card">
                    <h3>👥 好友管理</h3>
                    
                    <div class="form-group">
                        <input type="text" id="friend-uuid" placeholder="输入好友的UUID" style="margin-bottom: 10px;">
                        <button onclick="addFriend()" class="btn btn-primary" style="width: 100%;">添加好友</button>
                    </div>
                    
                    <h4>我的好友 ({len(friends)})</h4>
                    <div id="friends-list">
                        {friends_html}
                    </div>
                    
                    <h4>待处理请求 ({len(pending_requests)})</h4>
                    <div id="friend-requests">
                        {requests_html}
                    </div>
                </div>
                
                <!-- 群组管理卡片 -->
                <div class="card">
                    <h3>👨‍👩‍👧‍👦 群组管理</h3>
                    
                    <div class="form-group">
                        <input type="text" id="group-name" placeholder="群组名称" style="margin-bottom: 10px;">
                        <textarea id="group-description" placeholder="群组描述（可选）"></textarea>
                        <button onclick="createGroup()" class="btn btn-primary" style="width: 100%;">创建群组</button>
                    </div>
                    
                    <div class="form-group">
                        <input type="text" id="join-group-id" placeholder="输入群组ID" style="margin-bottom: 10px;">
                        <button onclick="joinGroup()" class="btn btn-success" style="width: 100%;">加入群组</button>
                    </div>
                    
                    <h4>我的群组 ({len(groups)})</h4>
                    <div id="groups-list">
                        {groups_html}
                    </div>
                </div>
                
                <!-- 消息卡片 -->
                <div class="card">
                    <h3>💬 最近消息</h3>
                    <div id="recent-messages">
                        {messages_html}
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // 添加好友
        function addFriend() {{
            const friendUuid = document.getElementById('friend-uuid').value.trim();
            
            if (!friendUuid) {{
                alert('请输入好友UUID');
                return;
            }}
            
            fetch('/add_friend', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/x-www-form-urlencoded',
                }},
                body: 'friend_uuid=' + encodeURIComponent(friendUuid)
            }})
            .then(response => response.json())
            .then(data => {{
                alert(data.message || data.error);
                if (data.message && !data.error) {{
                    document.getElementById('friend-uuid').value = '';
                    setTimeout(() => location.reload(), 1000);
                }}
            }})
            .catch(error => {{
                alert('网络错误: ' + error);
            }});
        }}
        
        // 创建群组
        function createGroup() {{
            const name = document.getElementById('group-name').value.trim();
            const description = document.getElementById('group-description').value.trim();
            
            if (!name) {{
                alert('请输入群组名称');
                return;
            }}
            
            const formData = new FormData();
            formData.append('name', name);
            formData.append('description', description);
            
            fetch('/create_group', {{
                method: 'POST',
                body: formData
            }})
            .then(response => response.json())
            .then(data => {{
                alert(data.message || data.error);
                if (data.message && !data.error) {{
                    document.getElementById('group-name').value = '';
                    document.getElementById('group-description').value = '';
                    setTimeout(() => location.reload(), 1000);
                }}
            }})
            .catch(error => {{
                alert('网络错误: ' + error);
            }});
        }}
        
        // 加入群组
        function joinGroup() {{
            const groupId = document.getElementById('join-group-id').value.trim();
            
            if (!groupId) {{
                alert('请输入群组ID');
                return;
            }}
            
            const formData = new FormData();
            formData.append('group_id', groupId);
            
            fetch('/join_group', {{
                method: 'POST',
                body: formData
            }})
            .then(response => response.json())
            .then(data => {{
                alert(data.message || data.error);
                if (data.message && !data.error) {{
                    document.getElementById('join-group-id').value = '';
                    setTimeout(() => location.reload(), 1000);
                }}
            }})
            .catch(error => {{
                alert('网络错误: ' + error);
            }});
        }}
        
        // 好友请求处理
        document.addEventListener('click', function(e) {{
            if (e.target.classList.contains('accept-friend')) {{
                const requestId = e.target.dataset.requestId;
                fetch('/accept_friend/' + requestId)
                    .then(response => response.json())
                    .then(data => {{
                        alert(data.message);
                        location.reload();
                    }});
            }}
            
            if (e.target.classList.contains('reject-friend')) {{
                const requestId = e.target.dataset.requestId;
                fetch('/reject_friend/' + requestId)
                    .then(response => response.json())
                    .then(data => {{
                        alert(data.message);
                        location.reload();
                    }});
            }}
        }});
        
        // 回车键支持
        document.getElementById('friend-uuid').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') addFriend();
        }});
        
        document.getElementById('group-name').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') createGroup();
        }});
        
        document.getElementById('join-group-id').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') joinGroup();
        }});
        </script>
    </body>
    </html>
    '''

# API路由
@app.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    friend_uuid = request.form.get('friend_uuid')
    
    if not friend_uuid:
        return jsonify({'error': '请输入好友UUID'}), 400
    
    if friend_uuid == current_user.id:
        return jsonify({'error': '不能添加自己为好友'}), 400
    
    friend = User.query.get(friend_uuid)
    if not friend:
        return jsonify({'error': '用户不存在'}), 404
    
    # 检查是否已经是好友
    existing_friendship = Friendship.query.filter_by(
        user_id=current_user.id, 
        friend_id=friend_uuid
    ).first()
    
    if existing_friendship:
        return jsonify({'error': '已经是好友关系'}), 400
    
    # 检查是否已有待处理的请求
    existing_request = FriendRequest.query.filter_by(
        from_user_id=current_user.id,
        to_user_id=friend_uuid,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'error': '已发送好友请求，等待对方处理'}), 400
    
    # 创建好友请求
    friend_request = FriendRequest(
        from_user_id=current_user.id,
        to_user_id=friend_uuid
    )
    
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({'message': f'已向 {friend.username} 发送好友请求'})

@app.route('/accept_friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    friend_request = FriendRequest.query.get(request_id)
    
    if friend_request and friend_request.to_user_id == current_user.id:
        # 创建双向好友关系
        friendship1 = Friendship(user_id=current_user.id, friend_id=friend_request.from_user_id)
        friendship2 = Friendship(user_id=friend_request.from_user_id, friend_id=current_user.id)
        
        friend_request.status = 'accepted'
        
        db.session.add_all([friendship1, friendship2])
        db.session.commit()
        
        return jsonify({'message': '好友添加成功'})
    
    return jsonify({'error': '操作失败'}), 400

@app.route('/reject_friend/<int:request_id>')
@login_required
def reject_friend(request_id):
    friend_request = FriendRequest.query.get(request_id)
    
    if friend_request and friend_request.to_user_id == current_user.id:
        friend_request.status = 'rejected'
        db.session.commit()
        
        return jsonify({'message': '已拒绝好友请求'})
    
    return jsonify({'error': '操作失败'}), 400

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name')
    description = request.form.get('description', '')
    
    if not name:
        return jsonify({'error': '群组名称不能为空'}), 400
    
    try:
        # 创建群组
        new_group = Group(
            name=name,
            description=description,
            creator_id=current_user.id
        )
        
        # 先保存群组以生成ID
        db.session.add(new_group)
        db.session.flush()  # 生成ID但不提交事务
        
        # 创建者自动加入群组并设为管理员
        group_member = GroupMember(
            group_id=new_group.id,
            user_id=current_user.id,
            role='admin'
        )
        
        db.session.add(group_member)
        db.session.commit()
        
        return jsonify({'message': '群组创建成功', 'group_id': new_group.id})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'创建群组失败: {str(e)}'}), 500

@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    group_id = request.form.get('group_id')
    
    if not group_id:
        return jsonify({'error': '请输入群组ID'}), 400
    
    group = Group.query.get(group_id)
    if not group:
        return jsonify({'error': '群组不存在'}), 404
    
    # 检查是否已是群成员
    existing_member = GroupMember.query.filter_by(
        group_id=group_id, 
        user_id=current_user.id
    ).first()
    
    if existing_member:
        return jsonify({'error': '已是群成员'}), 400
    
    group_member = GroupMember(
        group_id=group_id,
        user_id=current_user.id
    )
    
    db.session.add(group_member)
    db.session.commit()
    
    return jsonify({'message': f'成功加入群组: {group.name}'})

@app.route('/chat/<friend_id>')
@login_required
def chat(friend_id):
    friend = User.query.get(friend_id)
    if not friend:
        return redirect(url_for('dashboard'))
    
    # 验证是否是好友关系
    friendship = Friendship.query.filter_by(
        user_id=current_user.id,
        friend_id=friend_id
    ).first()
    
    if not friendship:
        return redirect(url_for('dashboard'))
    
    # 获取聊天记录
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.from_user_id == current_user.id) & (PrivateMessage.to_user_id == friend_id)) |
        ((PrivateMessage.from_user_id == friend_id) & (PrivateMessage.to_user_id == current_user.id))
    ).order_by(PrivateMessage.timestamp.asc()).all()
    
    messages_html = ''.join([f'''
        <div class="message {'sent' if message.from_user_id == current_user.id else 'received'}" data-message-id="{message.id}">
            <div class="message-content">{message.content}</div>
            <div class="message-time">{message.timestamp.strftime("%H:%M")}</div>
        </div>
    ''' for message in messages])
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>与 {friend.username} 聊天</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }}
            
            .chat-container {{
                flex: 1;
                display: flex;
                flex-direction: column;
                max-width: 800px;
                margin: 0 auto;
                background: white;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            
            .chat-header {{
                background: #007bff;
                color: white;
                padding: 20px;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .back-btn {{
                color: white;
                text-decoration: none;
                font-size: 1.2em;
                padding: 5px 10px;
                border-radius: 5px;
                transition: background 0.3s ease;
            }}
            
            .back-btn:hover {{
                background: rgba(255,255,255,0.2);
            }}
            
            .chat-messages {{
                flex: 1;
                padding: 20px;
                overflow-y: auto;
                max-height: 60vh;
                background: #f8f9fa;
            }}
            
            .message {{
                margin-bottom: 15px;
                max-width: 70%;
                padding: 12px 15px;
                border-radius: 18px;
                position: relative;
            }}
            
            .message.sent {{
                background: #007bff;
                color: white;
                margin-left: auto;
                border-bottom-right-radius: 5px;
            }}
            
            .message.received {{
                background: white;
                border: 1px solid #e0e0e0;
                margin-right: auto;
                border-bottom-left-radius: 5px;
            }}
            
            .message-content {{
                word-wrap: break-word;
            }}
            
            .message-time {{
                font-size: 0.7em;
                opacity: 0.7;
                margin-top: 5px;
            }}
            
            .chat-input {{
                padding: 20px;
                background: white;
                border-top: 1px solid #e0e0e0;
                display: flex;
                gap: 10px;
            }}
            
            .message-input {{
                flex: 1;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 25px;
                font-size: 14px;
                outline: none;
                transition: border-color 0.3s ease;
            }}
            
            .message-input:focus {{
                border-color: #007bff;
            }}
            
            .send-btn {{
                padding: 12px 25px;
                background: #007bff;
                color: white;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background 0.3s ease;
            }}
            
            .send-btn:hover {{
                background: #0056b3;
            }}
            
            .send-btn:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
        </style>
    </head>
    <body>
        <div class="chat-container">
            <div class="chat-header">
                <a href="/dashboard" class="back-btn">←</a>
                <div>
                    <h3>与 {friend.username} 聊天</h3>
                    <small>UUID: {friend.id}</small>
                </div>
            </div>
            
            <div class="chat-messages" id="chat-messages">
                {messages_html}
            </div>
            
            <div class="chat-input">
                <input type="text" class="message-input" id="message-input" placeholder="输入消息..." maxlength="500">
                <button class="send-btn" onclick="sendMessage()" id="send-btn">发送</button>
            </div>
        </div>
        
        <input type="hidden" id="friend-id" value="{friend.id}">
        
        <script>
        let lastMessageId = {messages[-1].id if messages else -1};
        let displayedMessageIds = new Set({[msg.id for msg in messages]});
        
        // 自动滚动到底部
        function scrollToBottom() {{
            const messagesDiv = document.getElementById('chat-messages');
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }}
        
        // 发送消息
        function sendMessage() {{
            const input = document.getElementById('message-input');
            const message = input.value.trim();
            const friendId = document.getElementById('friend-id').value;
            
            if (!message) return;
            
            // 立即显示自己的消息
            const messagesDiv = document.getElementById('chat-messages');
            const messageElement = document.createElement('div');
            messageElement.className = 'message sent';
            messageElement.innerHTML = `
                <div class="message-content">${{message}}</div>
                <div class="message-time">刚刚</div>
            `;
            messagesDiv.appendChild(messageElement);
            scrollToBottom();
            
            // 禁用输入和按钮
            input.disabled = true;
            document.getElementById('send-btn').disabled = true;
            
            fetch('/send_message', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/x-www-form-urlencoded',
                }},
                body: 'to_user_id=' + encodeURIComponent(friendId) + '&content=' + encodeURIComponent(message)
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    input.value = '';
                }} else {{
                    alert('发送失败: ' + (data.error || '未知错误'));
                    // 如果发送失败，移除刚刚显示的消息
                    if (messagesDiv.lastChild) {{
                        messagesDiv.removeChild(messagesDiv.lastChild);
                    }}
                }}
                
                // 重新启用输入和按钮
                input.disabled = false;
                document.getElementById('send-btn').disabled = false;
                input.focus();
            }})
            .catch(error => {{
                alert('网络错误: ' + error);
                // 如果网络错误，移除刚刚显示的消息
                const messagesDiv = document.getElementById('chat-messages');
                if (messagesDiv.lastChild) {{
                    messagesDiv.removeChild(messagesDiv.lastChild);
                }}
                input.disabled = false;
                document.getElementById('send-btn').disabled = false;
                input.focus();
            }});
        }}
        
        // 轮询新消息
        function pollMessages() {{
            fetch('/get_messages?last_id=' + lastMessageId)
                .then(response => response.json())
                .then(messages => {{
                    messages.forEach(msg => {{
                        if (msg.data.type === 'private_message' && 
                            msg.data.db_id && 
                            !displayedMessageIds.has(msg.data.db_id)) {{
                            
                            const messagesDiv = document.getElementById('chat-messages');
                            const messageElement = document.createElement('div');
                            
                            if (msg.data.from_user_id === '{current_user.id}') {{
                                messageElement.className = 'message sent';
                                messageElement.innerHTML = `
                                    <div class="message-content">${{msg.data.content}}</div>
                                    <div class="message-time">刚刚</div>
                                `;
                            }} else {{
                                messageElement.className = 'message received';
                                messageElement.innerHTML = `
                                    <div class="message-content">${{msg.data.content}}</div>
                                    <div class="message-time">刚刚</div>
                                `;
                            }}
                            
                            messagesDiv.appendChild(messageElement);
                            displayedMessageIds.add(msg.data.db_id);
                            lastMessageId = Math.max(lastMessageId, msg.id);
                        }}
                    }});
                    
                    scrollToBottom();
                    setTimeout(pollMessages, 1000);
                }})
                .catch(error => {{
                    setTimeout(pollMessages, 5000);
                }});
        }}
        
        // 回车发送
        document.getElementById('message-input').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                sendMessage();
            }}
        }});
        
        // 初始滚动到底部
        window.addEventListener('load', scrollToBottom);
        
        // 开始轮询
        pollMessages();
        </script>
    </body>
    </html>
    '''

@app.route('/group_chat/<group_id>')
@login_required
def group_chat(group_id):
    group = Group.query.get(group_id)
    if not group:
        return redirect(url_for('dashboard'))
    
    # 验证用户是否是群成员
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()
    
    if not membership:
        return redirect(url_for('dashboard'))
    
    # 获取群聊记录
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp.asc()).all()
    
    messages_html = ''.join([f'''
        <div class="message {'sent' if message.from_user_id == current_user.id else 'received'}" data-message-id="{message.id}">
            <div class="message-sender">{message.from_user.username if message.from_user_id != current_user.id else '我'}</div>
            <div class="message-content">{message.content}</div>
            <div class="message-time">{message.timestamp.strftime("%H:%M")}</div>
        </div>
    ''' for message in messages])
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>群聊 - {group.name}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                flex-direction: column;
            }}
            
            .chat-container {{
                flex: 1;
                display: flex;
                flex-direction: column;
                max-width: 800px;
                margin: 0 auto;
                background: white;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            
            .chat-header {{
                background: #28a745;
                color: white;
                padding: 20px;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .back-btn {{
                color: white;
                text-decoration: none;
                font-size: 1.2em;
                padding: 5px 10px;
                border-radius: 5px;
                transition: background 0.3s ease;
            }}
            
            .back-btn:hover {{
                background: rgba(255,255,255,0.2);
            }}
            
            .chat-messages {{
                flex: 1;
                padding: 20px;
                overflow-y: auto;
                max-height: 60vh;
                background: #f8f9fa;
            }}
            
            .message {{
                margin-bottom: 15px;
                max-width: 70%;
                padding: 12px 15px;
                border-radius: 18px;
                position: relative;
            }}
            
            .message.sent {{
                background: #007bff;
                color: white;
                margin-left: auto;
                border-bottom-right-radius: 5px;
            }}
            
            .message.received {{
                background: white;
                border: 1px solid #e0e0e0;
                margin-right: auto;
                border-bottom-left-radius: 5px;
            }}
            
            .message-sender {{
                font-size: 0.8em;
                opacity: 0.7;
                margin-bottom: 5px;
            }}
            
            .message-content {{
                word-wrap: break-word;
            }}
            
            .message-time {{
                font-size: 0.7em;
                opacity: 0.7;
                margin-top: 5px;
            }}
            
            .chat-input {{
                padding: 20px;
                background: white;
                border-top: 1px solid #e0e0e0;
                display: flex;
                gap: 10px;
            }}
            
            .message-input {{
                flex: 1;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 25px;
                font-size: 14px;
                outline: none;
                transition: border-color 0.3s ease;
            }}
            
            .message-input:focus {{
                border-color: #007bff;
            }}
            
            .send-btn {{
                padding: 12px 25px;
                background: #28a745;
                color: white;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background 0.3s ease;
            }}
            
            .send-btn:hover {{
                background: #1e7e34;
            }}
            
            .send-btn:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
        </style>
    </head>
    <body>
        <div class="chat-container">
            <div class="chat-header">
                <a href="/dashboard" class="back-btn">←</a>
                <div>
                    <h3>群聊 - {group.name}</h3>
                    <small>群组ID: {group.id}</small>
                </div>
            </div>
            
            <div class="chat-messages" id="chat-messages">
                {messages_html}
            </div>
            
            <div class="chat-input">
                <input type="text" class="message-input" id="message-input" placeholder="输入群消息..." maxlength="500">
                <button class="send-btn" onclick="sendGroupMessage()" id="send-btn">发送</button>
            </div>
        </div>
        
        <input type="hidden" id="group-id" value="{group.id}">
        
        <script>
        // 自动滚动到底部
        function scrollToBottom() {{
            const messagesDiv = document.getElementById('chat-messages');
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }}
        
        // 发送群消息
        function sendGroupMessage() {{
            const input = document.getElementById('message-input');
            const message = input.value.trim();
            const groupId = document.getElementById('group-id').value;
            
            if (!message) return;
            
            // 立即显示自己的消息
            const messagesDiv = document.getElementById('chat-messages');
            const messageElement = document.createElement('div');
            messageElement.className = 'message sent';
            messageElement.innerHTML = `
                <div class="message-sender">我</div>
                <div class="message-content">${{message}}</div>
                <div class="message-time">刚刚</div>
            `;
            messagesDiv.appendChild(messageElement);
            scrollToBottom();
            
            // 禁用输入和按钮
            input.disabled = true;
            document.getElementById('send-btn').disabled = true;
            
            fetch('/send_group_message', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/x-www-form-urlencoded',
                }},
                body: 'group_id=' + encodeURIComponent(groupId) + '&content=' + encodeURIComponent(message)
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    input.value = '';
                }} else {{
                    alert('发送失败: ' + (data.error || '未知错误'));
                    // 如果发送失败，移除刚刚显示的消息
                    if (messagesDiv.lastChild) {{
                        messagesDiv.removeChild(messagesDiv.lastChild);
                    }}
                }}
                
                // 重新启用输入和按钮
                input.disabled = false;
                document.getElementById('send-btn').disabled = false;
                input.focus();
            }})
            .catch(error => {{
                alert('网络错误: ' + error);
                // 如果网络错误，移除刚刚显示的消息
                const messagesDiv = document.getElementById('chat-messages');
                if (messagesDiv.lastChild) {{
                    messagesDiv.removeChild(messagesDiv.lastChild);
                }}
                input.disabled = false;
                document.getElementById('send-btn').disabled = false;
                input.focus();
            }});
        }}
        
        // 回车发送
        document.getElementById('message-input').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                sendGroupMessage();
            }}
        }});
        
        // 初始滚动到底部
        window.addEventListener('load', scrollToBottom);
        </script>
    </body>
    </html>
    '''

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    to_user_id = request.form.get('to_user_id')
    content = request.form.get('content')
    
    if not to_user_id or not content:
        return jsonify({'success': False, 'error': '缺少参数'})
    
    # 验证接收方是否存在且是好友
    to_user = User.query.get(to_user_id)
    friendship = Friendship.query.filter_by(
        user_id=current_user.id,
        friend_id=to_user_id
    ).first()
    
    if not to_user or not friendship:
        return jsonify({'success': False, 'error': '无法发送消息'})
    
    # 保存消息到数据库
    message = PrivateMessage(
        from_user_id=current_user.id,
        to_user_id=to_user_id,
        content=content.strip()
    )
    
    db.session.add(message)
    db.session.commit()
    
    # 创建消息数据用于实时通知
    message_data = {
        'type': 'private_message',
        'from_user_id': current_user.id,
        'from_username': current_user.username,
        'to_user_id': to_user_id,
        'content': content,
        'timestamp': message.timestamp.isoformat(),
        'db_id': message.id
    }
    
    # 添加到接收方的消息队列
    message_queue.add_message(to_user_id, message_data)
    
    return jsonify({'success': True, 'message_id': message.id})

@app.route('/send_group_message', methods=['POST'])
@login_required
def send_group_message():
    group_id = request.form.get('group_id')
    content = request.form.get('content')
    
    if not group_id or not content:
        return jsonify({'success': False, 'error': '缺少参数'})
    
    # 验证用户是否是群成员
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()
    
    if not membership:
        return jsonify({'success': False, 'error': '你不是群成员'})
    
    # 保存群消息到数据库
    message = GroupMessage(
        group_id=group_id,
        from_user_id=current_user.id,
        content=content.strip()
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({'success': True, 'message_id': message.id})

@app.route('/get_messages')
@login_required
def get_messages():
    last_id = int(request.args.get('last_id', -1))
    messages = message_queue.get_messages(current_user.id, last_id)
    
    # 定期清理过期消息
    if time.time() % 30 < 1:
        message_queue.clear_old_messages()
    
    return jsonify(messages)

# 辅助函数
def render_template_string(html_content, **context):
    from flask import render_template_string as flask_render_template_string
    return flask_render_template_string(html_content, **context)

# 初始化数据库
def init_db():
    with app.app_context():
        db.create_all()
        print("数据库初始化完成！")

# 启动应用
if __name__ == '__main__':
    # 检查数据库文件是否存在，如果不存在则初始化
    if not os.path.exists('social_platform.db'):
        init_db()
    
    print("社交平台启动中...")
    print("访问 http://localhost:5000 来使用平台")
    app.run(debug=True, host='0.0.0.0', port=23333)