from flask import Flask, jsonify, redirect, request, make_response
import os 
import sqlite3
from datetime import datetime, timedelta
from argon2 import PasswordHasher
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import send_from_directory
import os

ph = PasswordHasher()

db_path = os.path.join(os.path.dirname(__file__), 'webpy.db')

app = Flask(__name__)

# csrf = CSRFProtect(app)
# csrf.init_app(app)

app.secret_key = os.urandom(24)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # general limits for all routes
)

def generate_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redirects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            code TEXT NOT NULL,
            code_case BOOLEAN NOT NULL DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT 1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hash (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            hash TEXT NOT NULL,
            valid_until TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_login (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_redirect (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT
        )
    ''')
    cursor.execute('''SELECT * FROM user WHERE username=?''', ('admin',))
    row = cursor.fetchone()
    if not row:
        cursor.execute('INSERT INTO user (username, password) VALUES (?, ?)', ('admin', ph.hash('admin')))
    conn.commit()

    cursor.execute('''SELECT * FROM redirects WHERE code=?''', ('**',))
    row = cursor.fetchone()
    if not row:
        cursor.execute('INSERT INTO redirects (url, code) VALUES (?, ?)', ('*/login', '**'))
    conn.commit()

    cursor.execute('''SELECT * FROM redirects WHERE code=?''', ('*',))
    row = cursor.fetchone()
    if not row:
        cursor.execute('INSERT INTO redirects (url, code) VALUES (?, ?)', ('*/login', '*'))
    conn.commit()

    conn.close()

    print("Database generated and initialized.")

def log_redirect(code):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO log_redirect (code, timestamp) VALUES (?, ?)', (code, timestamp))
    conn.commit()
    conn.close()

def get_redirect_url(code):
    host = request.host_url
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Try exact match first
    cursor.execute('SELECT url FROM redirects WHERE code=?', (code,))
    row = cursor.fetchone()

    if not row:
        # Try lower-case fallback
        lower_code = code.lower()
        cursor.execute('SELECT url, code_case FROM redirects WHERE code=?', (lower_code,))
        row = cursor.fetchone()

        if row and row[1] != 'on':
            # Fallback to "**" wildcard
            cursor.execute('SELECT url FROM redirects WHERE code="**"')
            row = cursor.fetchone()

    conn.close()

    if row:
        url = row[0]
        if url.startswith('*/'):
            url = url.replace('*/', host)
        elif not url.startswith('https://'):
            url = 'https://' + url

        log_redirect(code)
        return url

    return None


def set_redirect_url(url, code, code_case=0):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM redirects WHERE code=?', (code,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO redirects (url, code, code_case) VALUES (?, ?, ?)', (url, code, code_case))
        conn.commit()
        conn.close()
        return True
    return False

def request_user(username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM user WHERE username=?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return

def set_hash(username, hash, valid_until):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO hash (username, hash, valid_until) VALUES (?, ?, ?)', (username, hash, valid_until))
    conn.commit()
    conn.close()

def get_hash(hash):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM hash WHERE hash=?', (hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return

def get_hash_user(hash):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM hash WHERE hash=?', (hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return

def check_hash(hash):
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM hash WHERE valid_until <= ?', (str(date),))

    cursor.execute('SELECT * FROM hash WHERE hash=?', (hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT active FROM user WHERE username=?', (row[1],))
        rowx = cursor.fetchone()
        if rowx and rowx[0] == 1:
            valid_until = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < valid_until:
                return True
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM hash WHERE hash=?', (hash,))
        conn.commit()
        conn.close()
    return False

def generate_hash(username):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash = secrets.token_urlsafe(64)
    return hash

def generate_valid_until():
    valid_until = datetime.now() + timedelta(days=1)
    return valid_until.strftime("%Y-%m-%d %H:%M:%S")

def get_or_create_csrf_token(response=None):
    token = request.cookies.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        if response:
            response.set_cookie("csrf_token", token, httponly=False, samesite='Strict')
    return token

def csrf_valid(request):
    token_form = request.form.get("csrf_token")
    token_cookie = request.cookies.get("csrf_token")
    return token_cookie and token_form and secrets.compare_digest(token_cookie, token_form)

def log(username, status):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO log_login (username, timestamp, status) VALUES (?, ?, ?)', (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status))
    conn.commit()
    conn.close()

cookie_hash = 'huP8Wq3zQKO3x2bXR8e6EAtlEzrvXzexpm9GuugJIcYAGBCwjXTz6tgH0IjGQWkg'

@app.route('/')
def root():
    return redirect(get_redirect_url('*'), code=302)

@app.route('/<path:path>')
def path(path):
    url = get_redirect_url(path)
    if url:
        return redirect(url, code=302)
    else:
        return redirect(get_redirect_url('**'), code=302)
    
@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("15 per minute")
def login():
    if request.cookies.get('session'):
        session = request.cookies.get('session')
        if check_hash(session):
            return redirect('/dashboard', code=302)

    if request.method == 'POST':
        if not csrf_valid(request):
            return "CSRF token invalid", 400

        username = request.form.get('username')
        password = request.form.get('password')
        request_user_hash = request_user(username)
        if request_user_hash is not None:
            try:
                if ph.verify(request_user_hash, password):
                    if ph.check_needs_rehash(request_user_hash):
                        request_user_hash = ph.hash(password)
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute('UPDATE user SET password=? WHERE username=?', (request_user_hash, username))
                        conn.commit()
                        conn.close()

                    response = make_response(redirect('/dashboard'))
                    hash = generate_hash(username)
                    valid_until = generate_valid_until()
                    response.set_cookie('session', hash, httponly=True, secure=True, samesite='Strict')
                    token = secrets.token_urlsafe(32)
                    response.set_cookie('csrf_token', token, httponly=False, secure=False, samesite='Strict')
                    set_hash(username, hash, valid_until)

                    log(username, 'success')
                    
                    return response
            except Exception as e:
                print(f"Login error: {e}")

        # login failed

        log(username, 'failed')

    # GET method: serve login form
    token = get_or_create_csrf_token()
    response = make_response(f"""
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
        <form action="/login" method="post">
            <input type="hidden" name="csrf_token" value="{token}"/>
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """)
    response.set_cookie('csrf_token', token, httponly=False, secure=False, samesite='Strict')
    return response
    
@app.route('/register', methods=['POST', 'GET'])
def register():
    session = request.cookies.get('session')
    if check_hash(session):
        if request.method == 'POST':
            if not csrf_valid(request):
                return "CSRF token invalid", 400
            username = request.form.get('username')
            password = ph.hash(request.form.get('password'))
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM user WHERE username=?', (username,))
            row = cursor.fetchone()
            if not row:
                cursor.execute('INSERT INTO user (username, password) VALUES (?, ?)', (username, password))

            conn.commit()
            conn.close()

            responable_user = get_hash_user(session)
            if responable_user:
                log(responable_user, 'new user created '+username)

            return redirect('/dashboard', code=302)
        else:
            
            token = get_or_create_csrf_token()
            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Register</title>
            </head>
            <body>
                <h1>Register</h1>
                <form action="/register" method="post">
                    <input type="hidden" name="csrf_token" value="{token}"/>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required><br><br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required><br><br>
                    <button type="submit">Register</button>
                </form>
            </body>
            </html>
            '''
    else:
        return redirect('/login', code=302)
    
@app.route('/logout', methods=['POST'])
def logout():
    session_token = request.cookies.get('session')
    
    if not csrf_valid(request):
        return "CSRF token invalid", 400

    if check_hash(session_token):
        log(get_hash_user(session_token), 'logout')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM hash WHERE hash=?', (session_token,))
        conn.commit()
        conn.close()
        response = app.make_response(redirect('/login'))
        response.set_cookie('session', '', expires=0, httponly=True, secure=True, samesite='Strict')
        response.set_cookie('csrf_token', '', expires=0, httponly=False, secure=False, samesite='Strict')
        return response
    else:
        return redirect('/login', code=302)
    
@app.route('/dashboard', methods=['GET'])
def dashboard():
    session = request.cookies.get('session')
    if check_hash(session):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, url, code, code_case FROM redirects')
        redirects = cursor.fetchall()
        conn.close()
        token = get_or_create_csrf_token()
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
        </head>
        <body>
            '''
        if request.args.get('error') == '400':
            html += '''
            <h1>Error</h1>
            <p>Invalid request.</p>
            '''
        html += f'''
            <h1>Dashboard</h1>
            <table border="1">
                <tr>
                    <th>URL</th>
                    <th>Code</th>
                </tr>
        '''
        for redi in redirects:
            html += f'''
                <tr>
                    <td>{redi[1]}</td>
                    <td>{redi[2]}</td>
                    <td>{redi[3]}</td>
                    <td>
                        <form action="/redirect/delete" method="post" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="{token}"/>
                            <input type="hidden" name="id" value="{redi[0]}">
                            <button type="submit">Remove</button>
                        </form>
                    </td>
                </tr>
            '''
        html += f'''
            </table>
            
            <h2>Add Redirect</h2>
            <form action="/redirect/add" method="post">
                <input type="hidden" name="csrf_token" value="{token}"/>
                <label for="url">URL:</label>
                <input type="text" id="url" name="url" required><br><br>
                <label for="code">Code:</label>
                <input type="text" id="code" name="code" required><br><br>
                <label for="code_case">Code Case:</label>
                <input type="checkbox" id="code_case" name="code_case"><br><br>
                <button type="submit">Add Redirect</button>
            </form>

            <h2>User Management</h2>
            <form action="/register" method="get">
                <input type="hidden" name="csrf_token" value="{token}"/>
                <button type="submit">Register User</button>
            </form>
            <table border="1">
                <tr>
                    <th>Username</th>
                    <th>Active</th>
                </tr>
            '''
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT username, active FROM user')
        users = cursor.fetchall()
        conn.close()
        for user in users:
            if user[0] != get_hash_user(session):
                html += f'''
                    <tr>
                        <td>{user[0]}</td>
                        <td>{user[1]}</td>
                        <td>
                            <form action="/user/swtich_status" method="post" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="{token}"/>
                                <input type="hidden" name="id" value="{user[0]}">
                                '''
                if user[1] == 0:
                    html += '''
                                <button type="submit">Activate</button>
                                '''
                else:
                    html += '''
                                <button type="submit">Deactivate</button>
                                '''
                html += f'''
                            </form>
                        </td>
                        <td>
                            <form action="/user/delete" method="post" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="{token}"/>
                                <input type="hidden" name="id" value="{user[0]}">
                                <button type="submit">Remove</button>
                            </form>
                        </td>
                    </tr>
                '''
            else:
                html += f'''
                    <tr>
                        <td>{user[0]}</td>
                        <td>{user[1]}</td>
                        <td>
                            <form action="/user/change_password" method="get" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="{token}"/>
                                <input type="hidden" name="id" value="{user[0]}">
                                <button type="submit" >Change Password</button>
                            </form>
                        </td>
                    <tr>
                        '''
        
        html += f'''
            </table>
            <h2>Logout</h2>
            <form action="/logout" method="post">
                <input type="hidden" name="csrf_token" value="{token}"/>
                <button type="submit">Logout</button>
            </form>

            <h2>User Logs</h2>
            <table border="1">
                <tr>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                </tr>
        '''
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT username, status, timestamp FROM log_login ORDER BY id DESC LIMIT 10')
        logs = cursor.fetchall()
        conn.close()
        for log in logs:
            html += f'''
                <tr>
                    <td>{log[0]}</td>
                    <td>{log[1]}</td>
                    <td>{log[2]}</td>
                </tr>
            '''
        html += f'''
            </table>
            <form action="/logs/login" method="get">
                <button type="submit">View Redirect Logs</button>
            </form>
            <h2>Redirect Logs</h2>
            <table border="1">
                <tr>
                    <th>Code</th>
                    <th>IP Address</th>
                    <th>Timestamp</th>
                </tr>
        '''
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT code, ip_address, timestamp FROM log_redirect ORDER BY id DESC LIMIT 10')
        logs = cursor.fetchall()
        conn.close()
        for log in logs:
            html += f'''
                <tr>
                    <td>{log[0]}</td>
                    <td>{log[1]}</td>
                    <td>{log[2]}</td>
                </tr>
            '''
        html += f'''
            </table>
            <form action="/logs/redirects" method="get">
                <button type="submit">View Redirect Logs</button>
            </form>
        </body>
        </html>
        '''
        return html
    else:
        return redirect('/login', code=302)
    
@app.route('/redirect/add', methods=['POST'])
def add_redirect():
    if request.method == 'POST':
        if not csrf_valid(request):
            return "CSRF token invalid", 400
        
        session = request.cookies.get('session')
        if check_hash(session):
            url = request.form.get('url')
            code = request.form.get('code')
            code_case = request.form.get('code_case')
            if not code_case:
                code_case = 0
            if set_redirect_url(url, code, code_case):
                return redirect('/dashboard', code=302)
            else:
                return redirect('/dashboard?error=400', code=302)
        else:
            return redirect('/login', code=302)

@app.route('/redirect/delete', methods=['POST'])
def delete_redirect():
    if request.method == 'POST':
        if not csrf_valid(request):
            return "CSRF token invalid", 400
        
        session = request.cookies.get('session')
        if check_hash(session):
            redirect_id = request.form.get('id')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM redirects WHERE id=?', (redirect_id,))
            conn.commit()
            conn.close()
            return redirect('/dashboard', code=302)
        else:
            return redirect('/login', code=302)
   
@app.route('/user/swtich_status', methods=['POST'])
def switch_user_status():
    if request.method == 'POST':
        if not csrf_valid(request):
            return "CSRF token invalid", 400
        
        session = request.cookies.get('session')
        if check_hash(session):
            username = request.form.get('id')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT active FROM user WHERE username=?', (username,))
            row = cursor.fetchone()
            if row:
                new_status = 0 if row[0] == 1 else 1
                cursor.execute('UPDATE user SET active=? WHERE username=?', (new_status, username))
                conn.commit()
            conn.close()

            log(get_hash_user(session), 'changed user status '+username)

            return redirect('/dashboard', code=302)
        else:
            return redirect('/login', code=302)
        
@app.route('/user/delete', methods=['POST'])
def delete_user():
    if request.method == 'POST':
        if not csrf_valid(request):
            return "CSRF token invalid", 400
        
        session = request.cookies.get('session')
        if check_hash(session):
            username = request.form.get('id')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM user WHERE username=?', (username,))
            conn.commit()
            conn.close()
            
            responable_user = get_hash_user(session)
            log(responable_user, 'deleted user '+username)

            return redirect('/dashboard', code=302)
        else:
            return redirect('/login', code=302)
        
@app.route('/user/change_password', methods=['POST', 'GET'])
def change_password():
    session = request.cookies.get('session')
    if check_hash(session):
        if request.method == 'POST':
            if not csrf_valid(request):
                return "CSRF token invalid", 400

            old_password = request.form.get('old_password')
            new_password = request.form.get('password')
            username = get_hash_user(session)
            request_user_hash = request_user(username)
            if request_user_hash is not None:
                try:
                    if ph.verify(request_user_hash, old_password):
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute('UPDATE user SET password=? WHERE username=?', (ph.hash(new_password), username))
                        conn.commit()
                        conn.close()
                        response = make_response(redirect('/dashboard'))
                        
                        log(username, 'password changed')

                        return response
                    
                except Exception as e:
                    print(f"Change password error: {e}")
                    return redirect('/dashboard?error=400', code=302)
            
            log(username, 'failed to change password')

        else:
            token = get_or_create_csrf_token()
            html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Change Password</title>
            </head>
            <body>
                <h1>Change Password</h1>
                <form action="/user/change_password" method="post">
                    <input type="hidden" name="csrf_token" value="{token}"/>
                    <label for="password">Old Password:</label>
                    <input type="password" id="old_password" name="old_password" required><br><br>
                    <label for="password">New Password:</label>
                    <input type="password" id="password" name="password" required><br><br>
                    <button type="submit">Change Password</button>
                </form>
            </body>
            </html>
            '''
            return html
        
    return redirect('/login', code=302)

@app.route('/logs/login', methods=['GET'])
def logs_login():
    session = request.cookies.get('session')
    if check_hash(session):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Logs</title>
        </head>
        <body>
            <h1>Login Logs</h1>
            <form action="/dashboard" method="get">
                <button type="submit">Back to Dashboard</button>
            </form>
            <table border="1">
                <tr>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                </tr>
        '''
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT username, status, timestamp FROM log_login ORDER BY id DESC LIMIT 30')
        logs = cursor.fetchall()
        conn.close()
        for log in logs:
            html += f'''
                <tr>
                    <td>{log[0]}</td>
                    <td>{log[1]}</td>
                    <td>{log[2]}</td>
                </tr>
            '''
        html += f'''
            </table>
        </body>
        </html>
        '''
        return html
    else:
        return redirect('/login', code=302)
    
@app.route('/logs/redirects', methods=['GET'])
def logs_redirects():
    session = request.cookies.get('session')
    if check_hash(session):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirect Logs</title>
        </head>
        <body>
            <h1>Redirect Logs</h1>
            <form action="/dashboard" method="get">
                <button type="submit">Back to Dashboard</button>
            </form>
            <table border="1">
                <tr>
                    <th>Code</th>
                    <th>IP Address</th>
                    <th>Timestamp</th>
                </tr>
        '''
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT code, ip_address, timestamp FROM log_redirect ORDER BY id DESC LIMIT 30')
        logs = cursor.fetchall()
        conn.close()
        for log in logs:
            html += f'''
                <tr>
                    <td>{log[0]}</td>
                    <td>{log[1]}</td>
                    <td>{log[2]}</td>
                </tr>
            '''
        html += f'''
            </table>
        </body>
        </html>
        '''
        return html
    else:
        return redirect('/login', code=302)

@app.route('/favicon.ico')
def favicon():
    favicon_path = os.path.join(os.path.dirname(__file__), 'favicon.ico')

    if os.path.exists(favicon_path):
        return send_from_directory(os.path.dirname(favicon_path), 'favicon.ico')
    else:
        return '', 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Too many requests. Please try again later."), 429

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response

if __name__ == '__main__':
    from waitress import serve
    generate_db()
    print('Starting server...')
    serve(app, host='0.0.0.0', port=8090)

# if __name__ == '__main__':
#     generate_db()
#     app.run(debug=True)