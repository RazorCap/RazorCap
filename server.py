from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import sqlite3
import os
import bcrypt
import requests
import uuid
import time
import json
import secrets
from functools import wraps
from core.solver import Hcaptcha
import threading

app = Flask(__name__, 
    static_folder='website/static',
    template_folder='website'
)
app.secret_key = os.environ.get('SECRET_KEY', 'razorcap_default_secret_key')

# Database setup
DB_PATH = "razorcap.db"

def init_db():
    # Initialize database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        api_key TEXT UNIQUE,
        created_at REAL,
        last_login REAL,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    # Create tasks table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        api_key TEXT,
        task_type TEXT,
        sitekey TEXT,
        siteurl TEXT,
        proxy TEXT,
        rqdata TEXT,
        status TEXT,
        solution TEXT,
        error TEXT,
        created_at REAL
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error_message='Username and password are required')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            return render_template('login.html', error_message='Invalid username or password')
        
        # Update last login time
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user[0]))
        conn.commit()
        conn.close()
        
        session['user_id'] = user[0]
        session['username'] = username
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not username or not password or not confirm_password:
            return render_template('register.html', error_message='All fields are required')
        
        if password != confirm_password:
            return render_template('register.html', error_message='Passwords do not match')
        
        
        # Check if username already exists
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return render_template('register.html', error_message='Username already exists')
        
        # Generate API key
        api_key = secrets.token_hex(16)
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert user into database
        try:
            cursor.execute(
                "INSERT INTO users (username, password, api_key, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
                (username, hashed_password.decode('utf-8'), api_key, time.time(), time.time())
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            # Set session
            session['user_id'] = user_id
            session['username'] = username
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.close()
            return render_template('register.html', error_message=f'Registration failed: {str(e)}')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user details
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, api_key FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=user[0], api_key=user[1])

# Dashboard API endpoints
@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Get user details based on API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    return jsonify({
        'status': 'success',
        'username': user[0]
    })

@app.route('/session_info', methods=['GET'])
@login_required
def session_info():
    return jsonify({
        'status': 'success',
        'username': session.get('username', 'User')
    })

@app.route('/get_api_key', methods=['GET'])
@login_required
def get_api_key():
    # Get user's API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT api_key FROM users WHERE id = ?", (session['user_id'],))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'status': 'error', 'message': 'User not found'})
    
    return jsonify({
        'status': 'success',
        'api_key': result[0]
    })

@app.route('/get_balance', methods=['POST'])
def get_balance():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Since we don't have a balance table yet, we'll just return a mock balance
    # In a real application, you would query the user's balance from a database
    
    # This is a placeholder - you'll need to implement actual balance tracking
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Mock balance based on user ID (just for demonstration)
    mock_balance = float(user[0]) * 10.5  # Just a placeholder value
    
    return jsonify({
        'status': 'success',
        'balance': mock_balance
    })

@app.route('/get_daily_usage', methods=['POST'])
def get_daily_usage():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Verify API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Mock daily usage (you would replace this with actual usage tracking)
    daily_requests = user[0] * 3  # Just a placeholder
    
    return jsonify({
        'status': 'success',
        'daily_requests': daily_requests
    })

@app.route('/get_success_rate', methods=['POST'])
def get_success_rate():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Verify API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Mock success rate (you would replace this with actual success rate calculation)
    # Using user ID to generate different values for different users
    success_rate = 85 + (user[0] % 15)  # Between 85% and 99%
    
    return jsonify({
        'status': 'success',
        'success_rate': success_rate
    })

@app.route('/get_recent_tasks', methods=['POST'])
def get_recent_tasks():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    limit = data.get('limit', 5)  # Default to 5 recent tasks
    
    # Verify API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get recent tasks from database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT task_id, task_type, status, created_at FROM tasks WHERE api_key = ? ORDER BY created_at DESC LIMIT ?",
        (api_key, limit)
    )
    tasks = cursor.fetchall()
    conn.close()
    
    # Format tasks for response
    formatted_tasks = []
    for task in tasks:
        task_id, task_type, status, timestamp = task
        formatted_tasks.append({
            'id': task_id,
            'type': task_type,
            'status': status,
            'timestamp': timestamp
        })
    
    return jsonify({
        'status': 'success',
        'tasks': formatted_tasks
    })

@app.route('/get_task_history', methods=['POST'])
def get_task_history():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    page = data.get('page', 1)
    date_filter = data.get('date_filter', 'all')
    status_filter = data.get('status_filter', 'all')
    
    # Verify API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Build query based on filters
    query = "SELECT task_id, task_type, status, created_at FROM tasks WHERE api_key = ?"
    params = [api_key]
    
    # Apply date filter
    current_time = time.time()
    if date_filter == 'today':
        query += " AND created_at >= ?"
        params.append(current_time - 24*3600)  # Last 24 hours
    elif date_filter == 'yesterday':
        query += " AND created_at >= ? AND created_at < ?"
        params.append(current_time - 48*3600)  # 24-48 hours ago
        params.append(current_time - 24*3600)
    elif date_filter == 'week':
        query += " AND created_at >= ?"
        params.append(current_time - 7*24*3600)  # Last 7 days
    elif date_filter == 'month':
        query += " AND created_at >= ?"
        params.append(current_time - 30*24*3600)  # Last 30 days
    
    # Apply status filter
    if status_filter != 'all':
        query += " AND status = ?"
        params.append(status_filter)
    
    # Get total count for pagination
    count_query = query.replace("SELECT task_id, task_type, status, created_at", "SELECT COUNT(*)")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(count_query, params)
    total_tasks = cursor.fetchone()[0]
    conn.close()
    
    # Apply pagination
    per_page = 10
    total_pages = (total_tasks + per_page - 1) // per_page
    
    if page < 1 or page > total_pages:
        page = 1
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.append(per_page)
    params.append((page - 1) * per_page)
    
    # Get paginated tasks
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query, params)
    tasks = cursor.fetchall()
    conn.close()
    
    # Format tasks for response
    formatted_tasks = []
    for task in tasks:
        task_id, task_type, status, timestamp = task
        formatted_tasks.append({
            'id': task_id,
            'type': task_type,
            'status': status,
            'timestamp': timestamp,
            'details': f"Task details for {task_id}"
        })
    
    return jsonify({
        'status': 'success',
        'tasks': formatted_tasks,
        'total_pages': total_pages,
        'current_page': page
    })

@app.route('/reset_key', methods=['POST'])
@login_required
def reset_key():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'Current API key is required'})
    
    # Generate a new API key
    new_key = secrets.token_hex(16)
    
    # Update the API key in the database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'new_key': new_key
    })

# API Key Validation Functions
def validate_api_key(api_key):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, "Invalid API key"
        
        return True, "Valid API key"
    except Exception as e:
        return False, str(e)

def increment_api_key_usage(api_key):
    # This is a placeholder function - in a real app, you would track usage
    return True

# Solver Class
class Solver:
    def __init__(self, api_key):
        self.api_key = api_key
        
    def solve(self, sitekey, siteurl, proxy=None, rqdata=None):
        try:
            # Validate API key
            valid, message = validate_api_key(self.api_key)
            if not valid:
                return "error_" + message
            
            # Create and solve captcha
            captcha = Hcaptcha(sitekey, siteurl, proxy, rqdata)
            result = captcha.solve()
            
            if result == "None":
                return "error"
            
            # Increment API key usage
            increment_api_key_usage(self.api_key)
            
            return result
        except Exception as e:
            print(f"Error solving captcha: {e}")
            return "error"
    
    def create_task(self, task_type, sitekey, siteurl, proxy=None, rqdata=None):
        try:
            # Validate API key
            valid, message = validate_api_key(self.api_key)
            if not valid:
                return False, message
            
            # Generate a unique task ID
            task_id = str(uuid.uuid4())
            
            # Store in database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO tasks 
            (task_id, api_key, task_type, sitekey, siteurl, proxy, rqdata, status, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_id, 
                self.api_key, 
                task_type, 
                sitekey, 
                siteurl, 
                proxy, 
                rqdata, 
                "solving", 
                time.time()
            ))
            conn.commit()
            conn.close()
            
            # Start a thread to solve the captcha
            thread = threading.Thread(
                target=self._task_solver,
                args=(task_id, task_type, sitekey, siteurl, proxy, rqdata)
            )
            
            # Start the thread
            thread.daemon = True
            thread.start()
            
            return True, task_id
        except Exception as e:
            print(f"Error creating task: {e}")
            return False, str(e)
    
    def _task_solver(self, task_id, task_type, sitekey, siteurl, proxy, rqdata):
        try:
            # Create and solve captcha
            captcha = Hcaptcha(sitekey, siteurl, proxy, rqdata)
            result = captcha.solve()
            
            # Update task in database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if result == "None":
                cursor.execute(
                    "UPDATE tasks SET status = ?, error = ? WHERE task_id = ?", 
                    ("error", "Failed to solve captcha", task_id)
                )
            else:
                cursor.execute(
                    "UPDATE tasks SET status = ?, solution = ? WHERE task_id = ?", 
                    ("solved", result, task_id)
                )
                
                # Increment API key usage on successful solve
                increment_api_key_usage(self.api_key)
            
            conn.commit()
            conn.close()
        except Exception as e:
            # Update task with error
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE tasks SET status = ?, error = ? WHERE task_id = ?", 
                ("error", str(e), task_id)
            )
            conn.commit()
            conn.close()
    
    def get_task_solution(self, task_id):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT status, solution, error, api_key FROM tasks WHERE task_id = ?", (task_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return "not_found", None
            
            status, solution, error, task_api_key = result
            
            # Verify that the API key matches the task
            if task_api_key != self.api_key:
                return "unauthorized", None
            
            if status == "solving":
                return "solving", None
            elif status == "error":
                return "error", error
            elif status == "solved":
                return "solved", solution
            
            return "unknown", None
        except Exception as e:
            print(f"Error getting task solution: {e}")
            return "error", str(e)

# API Endpoints
@app.route('/create_task', methods=['POST'])
def create_task():
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    task_type = data.get('type', 'hcaptcha_basic')
    if task_type not in ['hcaptcha_basic', 'enterprise']:
        return jsonify({"status": "error", "message": "Invalid task type"}), 400
    
    task_data = data.get('data', {})
    if not task_data:
        return jsonify({"status": "error", "message": "Task data is required"}), 400
    
    sitekey = task_data.get('sitekey')
    if not sitekey:
        return jsonify({"status": "error", "message": "Site key is required"}), 400
    
    siteurl = task_data.get('siteurl', 'discord.com')
    proxy = task_data.get('proxy', '')
    rqdata = task_data.get('rqdata')
    
    solver = Solver(api_key)
    success, result = solver.create_task(task_type, sitekey, siteurl, proxy, rqdata)
    
    if not success:
        return jsonify({"status": "error", "message": result}), 500
    
    return jsonify({"status": "success", "task_id": result})

@app.route('/get_result/<task_id>', methods=['GET'])
def get_result(task_id):
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    solver = Solver(api_key)
    status, result = solver.get_task_solution(task_id)
    
    if status == "not_found":
        return jsonify({"status": "error", "message": "Task not found"}), 404
    elif status == "unauthorized":
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    elif status == "solving":
        return jsonify({"status": "solving"})
    elif status == "error":
        return jsonify({"status": "error", "message": result}), 500
    elif status == "solved":
        return jsonify({"status": "success", "solution": result})
    
    return jsonify({"status": "error", "message": "Unknown error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True) 