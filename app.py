from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify
import sqlite3
import os
import subprocess
import hashlib
import requests
try:
    from config import current_config, ADMIN_CREDENTIALS, API_KEYS, DATABASE_CONFIG, EXTERNAL_SERVICES
except ImportError:
    # Fallback if config.py is not available
    class Config:
        SECRET_KEY = 'dev-secret-key-12345'
        DEBUG = True
        SERVER_CONFIG = {'host': '0.0.0.0', 'port': 5000, 'internal_ip': '10.0.0.100'}
    
    current_config = Config()
    ADMIN_CREDENTIALS = {'username': 'admin', 'password': 'Admin@123', 'email': 'admin@example.com'}
    API_KEYS = {'openai_api_key': 'sk-proj-1234567890abcdef'}
    DATABASE_CONFIG = {'host': '192.168.1.50', 'username': 'db_admin', 'password': 'MySecretDB@2024!'}
    EXTERNAL_SERVICES = {'redis_url': 'redis://admin:password123@192.168.1.60:6379/0'}

app = Flask(__name__)

# Using configuration from config.py
app.secret_key = current_config.SECRET_KEY
app.config['DEBUG'] = current_config.DEBUG

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    ''')
    
    # Insert admin from config
    cursor.execute("INSERT OR REPLACE INTO users (id, username, password, email, role) VALUES (1, ?, ?, ?, 'admin')",
                  (ADMIN_CREDENTIALS['username'], ADMIN_CREDENTIALS['password'], ADMIN_CREDENTIALS['email']))
    cursor.execute("INSERT OR REPLACE INTO users (id, username, password, email, role) VALUES (2, 'user', '123456', 'user@example.com', 'user')")
    cursor.execute("INSERT OR REPLACE INTO users (id, username, password, email, role) VALUES (3, 'test', 'test', 'test@example.com', 'user')")
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Web Application</title>
        <!-- Vulnerability: Information disclosure in comments -->
        <!-- Config file: config.py contains all secrets -->
        <!-- Database: vulnerable_app.db -->
        <!-- Admin panel: /admin -->
        <!-- API endpoints: /api/users, /api/config, /api/secrets -->
        <!-- Debug info: /debug -->
    </head>
    <body>
        <h1>Welcome to Vulnerable Flask App</h1>
        <p>This application contains multiple security vulnerabilities for educational testing.</p>
        <ul>
            <li><a href="/login">Login Page</a></li>
            <li><a href="/search">Search Users (Command Injection)</a></li>
            <li><a href="/upload">File Upload (Unrestricted)</a></li>
            <li><a href="/admin">Admin Panel (IDOR)</a></li>
            <li><a href="/api/config">API Configuration (Data Exposure)</a></li>
            <li><a href="/api/secrets">API Secrets (Sensitive Data)</a></li>
            <li><a href="/debug">Debug Information</a></li>
            <li><a href="/template">Template Engine (SSTI)</a></li>
        </ul>
        <hr>
        <small>Server IP: {server_ip} | Environment: {env}</small>
    </body>
    </html>
    '''.format(
        server_ip=current_config.SERVER_CONFIG['internal_ip'], 
        env='Development' if current_config.DEBUG else 'Production'
    )
    return html_template

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerability: SQL Injection
        conn = sqlite3.connect('vulnerable_app.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"Executing query: {query}")  # Vulnerability: Logging sensitive data
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login', error='Invalid credentials'))
    
    # Vulnerability: Reflected XSS
    error_msg = request.args.get('error', '')
    login_form = f'''
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Login to Vulnerable App</h2>
        <div style="color: red;">{error_msg}</div>
        <form method="POST">
            Username: <input type="text" name="username" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            <input type="submit" value="Login">
        </form>
        <p><small>Try: admin/Admin@123 or test SQL injection: admin' OR '1'='1' --</small></p>
        <a href="/">Back to Home</a>
    </body>
    </html>
    '''
    return login_form

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return f'''
    <h2>Dashboard - Welcome {session['username']}</h2>
    <p>Role: {session['role']}</p>
    <p>Server: {current_config.SERVER_CONFIG['internal_ip']}</p>
    <p>Database Host: {DATABASE_CONFIG['host']}</p>
    <ul>
        <li><a href="/profile">View Profile</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/api/config">System Config</a></li>
        <li><a href="/logout">Logout</a></li>
    </ul>
    '''

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_term = request.form['search']
        
        # Vulnerability: Command Injection
        try:
            # Dangerous: User input directly in shell command
            result = subprocess.check_output(f'echo "Search results for: {search_term}" && ls -la', shell=True, text=True)
            return f"<h2>Search Results:</h2><pre>{result}</pre><br><a href='/search'>Search Again</a> | <a href='/'>Home</a>"
        except Exception as e:
            return f"Search error: {str(e)}"
    
    return '''
    <h2>User Search (Command Injection Test)</h2>
    <form method="POST">
        Search Term: <input type="text" name="search" placeholder="Try: test; whoami" required><br><br>
        <input type="submit" value="Search">
    </form>
    <p><small>Test command injection: test; whoami; ls -la</small></p>
    <a href="/">Home</a>
    '''

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file uploaded'
        
        file = request.files['file']
        if file.filename == '':
            return 'No file selected'
        
        # Vulnerability: Unrestricted file upload - no validation
        upload_path = os.path.join('uploads', file.filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(upload_path)
        
        return f'''
        <h2>File Upload Success</h2>
        <p>File: {file.filename}</p>
        <p>Saved to: {upload_path}</p>
        <p>File size: {os.path.getsize(upload_path)} bytes</p>
        <a href="/upload">Upload Another</a> | <a href="/">Home</a>
        '''
    
    return '''
    <h2>File Upload (No Restrictions)</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br><br>
        <input type="submit" value="Upload File">
    </form>
    <p><small>Try uploading dangerous file types: .php, .jsp, .py, .sh</small></p>
    <a href="/">Home</a>
    '''

@app.route('/admin')
def admin():
    # Vulnerability: Insecure Direct Object Reference + Missing Authorization
    user_id = request.args.get('user_id', session.get('user_id', '1'))
    
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return f'''
        <h2>Admin Panel - User Details</h2>
        <p><strong>User ID:</strong> {user_data[0]}</p>
        <p><strong>Username:</strong> {user_data[1]}</p>
        <p><strong>Password:</strong> {user_data[2]}</p>
        <p><strong>Email:</strong> {user_data[3]}</p>
        <p><strong>Role:</strong> {user_data[4]}</p>
        <hr>
        <p><small>Try: /admin?user_id=1 or /admin?user_id=2</small></p>
        <a href="/">Home</a>
        '''
    return "User not found"

@app.route('/api/config')
def api_config():
    # Vulnerability: Sensitive configuration exposure
    exposed_config = {
        "application": {
            "secret_key": app.secret_key,
            "debug_mode": app.config['DEBUG']
        },
        "database": DATABASE_CONFIG,
        "server": current_config.SERVER_CONFIG,
        "admin": ADMIN_CREDENTIALS,
        "environment": "development" if current_config.DEBUG else "production"
    }
    return jsonify(exposed_config)

@app.route('/api/secrets')
def api_secrets():
    # Vulnerability: API keys and secrets exposure
    return jsonify({
        "api_keys": API_KEYS,
        "external_services": EXTERNAL_SERVICES,
        "backup_credentials": {
            "ftp_server": "backup.company.com",
            "ftp_user": "backup_admin",
            "ftp_pass": "BackupPass2024!"
        },
        "internal_tokens": {
            "jwt_secret": "super-secret-jwt-key-2024",
            "csrf_token": "csrf-token-12345",
            "api_token": "internal-api-token-xyz789"
        }
    })

@app.route('/api/users')
def api_users():
    # Vulnerability: No authentication required for sensitive data
    conn = sqlite3.connect('vulnerable_app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, email, role FROM users")  # Password included!
    users = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        "id": user[0],
        "username": user[1], 
        "password": user[2],  # Vulnerability: Password in API response
        "email": user[3],
        "role": user[4]
    } for user in users])

@app.route('/debug')
def debug_info():
    # Vulnerability: Debug information exposure
    debug_data = {
        "environment_variables": dict(os.environ),
        "current_directory": os.getcwd(),
        "python_path": os.sys.path,
        "loaded_modules": list(os.sys.modules.keys()),
        "flask_config": dict(app.config),
        "session_data": dict(session)
    }
    
    return f'''
    <h2>Debug Information</h2>
    <pre>{str(debug_data)}</pre>
    <a href="/">Home</a>
    '''

@app.route('/template')
def template():
    # Vulnerability: Server-Side Template Injection
    name = request.args.get('name', 'World')
    # Direct template rendering without escaping
    template = f"<h1>Hello {name}!</h1><p>Welcome to our app!</p>"
    return render_template_string(template)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    # Vulnerability: Running on all interfaces in debug mode
    app.run(
        host=current_config.SERVER_CONFIG['host'], 
        port=current_config.SERVER_CONFIG['port'], 
        debug=current_config.DEBUG
    )