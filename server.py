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
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__, 
    static_folder='website/static',
    template_folder='website'
)
app.secret_key = os.environ.get('SECRET_KEY', 'razorcap_default_secret_key')

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add Jinja2 filters
@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert a timestamp to a formatted date string."""
    if not timestamp:
        return ""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

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
    
    # Create balance table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS balance (
        user_id INTEGER PRIMARY KEY,
        amount REAL DEFAULT 0.0,
        last_updated REAL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create transactions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        type TEXT,
        description TEXT,
        created_at REAL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at REAL
    )
    ''')
    
    # Insert default settings if they don't exist
    cursor.execute("SELECT * FROM settings WHERE key = 'basic_cost_per_1k'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ('basic_cost_per_1k', '3.0', time.time())
        )
    
    cursor.execute("SELECT * FROM settings WHERE key = 'enterprise_cost_per_1k'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ('enterprise_cost_per_1k', '5.0', time.time())
        )
    
    cursor.execute("SELECT * FROM settings WHERE key = 'min_balance'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ('min_balance', '0.0', time.time())
        )
    
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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
        result = cursor.fetchone()
        conn.close()
        
        if not result or not result[0]:
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        
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
        cursor.execute("SELECT id, password, is_admin FROM users WHERE username = ?", (username,))
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
        session['is_admin'] = user[2]
        
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
        
        # Generate API key as UUID (GUID)
        api_key = str(uuid.uuid4())
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Set admin status if username is 'admin'
        is_admin = 1 if username.lower() == 'admin' else 0
        
        # Insert user into database
        try:
            cursor.execute(
                "INSERT INTO users (username, password, api_key, created_at, last_login, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
                (username, hashed_password.decode('utf-8'), api_key, time.time(), time.time(), is_admin)
            )
            user_id = cursor.lastrowid
            
            # Initialize balance for new user
            cursor.execute(
                "INSERT INTO balance (user_id, amount, last_updated) VALUES (?, ?, ?)",
                (user_id, 0.0, time.time())  # Start with 0.0 credits instead of 10.0
            )
            
            # No initial balance transaction needed since balance is 0
            
            conn.commit()
            conn.close()
            
            # Set session
            session['user_id'] = user_id
            session['username'] = username
            session['is_admin'] = is_admin
            
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
    cursor.execute("SELECT username, api_key, is_admin FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # If user is not found, clear session and redirect to login
    if not user:
        session.clear()
        conn.close()
        return redirect(url_for('login'))
    
    # Get user balance
    cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (session['user_id'],))
    balance_result = cursor.fetchone()
    balance = balance_result[0] if balance_result else 0.0
    
    # Get recent transactions
    cursor.execute(
        "SELECT amount, type, description, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
        (session['user_id'],)
    )
    transactions = cursor.fetchall()
    
    # Get recent tasks
    cursor.execute(
        "SELECT task_id, task_type, status, created_at FROM tasks WHERE api_key = ? ORDER BY created_at DESC LIMIT 5",
        (user[1],)
    )
    tasks = cursor.fetchall()
    
    conn.close()
    
    return render_template(
        'dashboard.html', 
        username=user[0], 
        api_key=user[1], 
        is_admin=user[2],
        balance=balance,
        transactions=transactions,
        tasks=tasks
    )

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get all users
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, created_at, last_login, is_admin FROM users")
    users = cursor.fetchall()
    
    # Get system settings
    cursor.execute("SELECT key, value FROM settings")
    settings = cursor.fetchall()
    
    # Get recent transactions
    cursor.execute(
        "SELECT t.id, u.username, t.amount, t.type, t.description, t.created_at FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 10"
    )
    transactions = cursor.fetchall()
    
    # Get recent tasks
    cursor.execute(
        "SELECT t.task_id, u.username, t.task_type, t.status, t.created_at FROM tasks t JOIN users u ON t.api_key = u.api_key ORDER BY t.created_at DESC LIMIT 10"
    )
    tasks = cursor.fetchall()
    
    conn.close()
    
    return render_template(
        'admin.html',
        users=users,
        settings=settings,
        transactions=transactions,
        tasks=tasks
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, created_at, last_login, is_admin FROM users")
    users = cursor.fetchall()
    
    # Get balance for each user
    user_balances = {}
    for user in users:
        cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (user[0],))
        balance_result = cursor.fetchone()
        user_balances[user[0]] = balance_result[0] if balance_result else 0.0
    
    conn.close()
    
    return render_template('admin_users.html', users=users, user_balances=user_balances)

@app.route('/admin/add_balance', methods=['POST'])
@admin_required
def admin_add_balance():
    user_id = request.form.get('user_id')
    amount = float(request.form.get('amount', 0))
    description = request.form.get('description', 'Admin credit')
    
    if not user_id or amount <= 0:
        flash('Invalid input', 'error')
        return redirect(url_for('admin_users'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get current balance
    cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (user_id,))
    balance_result = cursor.fetchone()
    
    if not balance_result:
        # Create balance record if it doesn't exist
        cursor.execute(
            "INSERT INTO balance (user_id, amount, last_updated) VALUES (?, ?, ?)",
            (user_id, amount, time.time())
        )
        new_balance = amount
    else:
        # Update existing balance
        new_balance = balance_result[0] + amount
        cursor.execute(
            "UPDATE balance SET amount = ?, last_updated = ? WHERE user_id = ?",
            (new_balance, time.time(), user_id)
        )
    
    # Add transaction record
    cursor.execute(
        "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, amount, 'credit', description, time.time())
    )
    
    conn.commit()
    conn.close()
    
    flash(f'Added {amount} credits to user {user_id}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        basic_cost = float(request.form.get('basic_cost_per_1k', 3.0))
        enterprise_cost = float(request.form.get('enterprise_cost_per_1k', 5.0))
        min_balance = float(request.form.get('min_balance', 0.0))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE settings SET value = ?, updated_at = ? WHERE key = ?",
            (str(basic_cost), time.time(), 'basic_cost_per_1k')
        )
        
        cursor.execute(
            "UPDATE settings SET value = ?, updated_at = ? WHERE key = ?",
            (str(enterprise_cost), time.time(), 'enterprise_cost_per_1k')
        )
        
        cursor.execute(
            "UPDATE settings SET value = ?, updated_at = ? WHERE key = ?",
            (str(min_balance), time.time(), 'min_balance')
        )
        
        conn.commit()
        conn.close()
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin_settings'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = cursor.fetchall()
    conn.close()
    
    settings_dict = {key: value for key, value in settings}
    
    return render_template('admin_settings.html', settings=settings_dict)

# Dashboard API endpoints
@app.route('/get_user_info', methods=['POST'])
@csrf.exempt
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
@csrf.exempt
def session_info():
    return jsonify({
        'status': 'success',
        'username': session.get('username', 'User'),
        'is_admin': session.get('is_admin', 0)
    })

@app.route('/get_api_key', methods=['GET'])
@login_required
@csrf.exempt
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
@csrf.exempt
def get_balance():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Get user ID from API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    user_id = user[0]
    
    # Get balance from balance table
    cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (user_id,))
    balance_result = cursor.fetchone()
    
    if not balance_result:
        # If no balance record exists, create one with default value
        cursor.execute(
            "INSERT INTO balance (user_id, amount, last_updated) VALUES (?, ?, ?)",
            (user_id, 0.0, time.time())
        )
        conn.commit()
        balance = 0.0
    else:
        balance = balance_result[0]
    
    conn.close()
    
    return jsonify({
        'status': 'success',
        'balance': balance
    })

@app.route('/get_daily_usage', methods=['POST'])
@csrf.exempt
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
    
    if not user:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    user_id = user[0]
    
    # Get daily usage from tasks table
    current_time = time.time()
    day_ago = current_time - 24*3600
    
    cursor.execute(
        "SELECT COUNT(*) FROM tasks WHERE api_key = ? AND created_at >= ?",
        (api_key, day_ago)
    )
    daily_requests = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'status': 'success',
        'daily_requests': daily_requests
    })

@app.route('/get_success_rate', methods=['POST'])
@csrf.exempt
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
    
    if not user:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get success rate from tasks table
    cursor.execute(
        "SELECT COUNT(*) FROM tasks WHERE api_key = ? AND status = 'solved'",
        (api_key,)
    )
    solved_count = cursor.fetchone()[0]
    
    cursor.execute(
        "SELECT COUNT(*) FROM tasks WHERE api_key = ? AND status IN ('solved', 'error')",
        (api_key,)
    )
    total_count = cursor.fetchone()[0]
    
    conn.close()
    
    # Calculate success rate
    success_rate = 0
    if total_count > 0:
        success_rate = (solved_count / total_count) * 100
    
    return jsonify({
        'status': 'success',
        'success_rate': success_rate
    })

@app.route('/get_recent_tasks', methods=['POST'])
@csrf.exempt
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
    
    if not user:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get recent tasks from database
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
@csrf.exempt
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
    
    if not user:
        conn.close()
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
    cursor.execute(count_query, params)
    total_tasks = cursor.fetchone()[0]
    
    # Apply pagination
    per_page = 10
    total_pages = (total_tasks + per_page - 1) // per_page
    
    if page < 1 or page > total_pages:
        page = 1
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.append(per_page)
    params.append((page - 1) * per_page)
    
    # Get paginated tasks
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
@csrf.exempt
def reset_key():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'Current API key is required'})
    
    # Generate a new API key as UUID (GUID)
    new_key = str(uuid.uuid4())
    
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

@app.route('/get_transactions', methods=['POST'])
@csrf.exempt
def get_transactions():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    limit = data.get('limit', 10)  # Default to 10 transactions
    
    # Verify API key
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    user_id = user[0]
    
    # Get transactions from database
    cursor.execute(
        "SELECT amount, type, description, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit)
    )
    transactions = cursor.fetchall()
    conn.close()
    
    # Format transactions for response
    formatted_transactions = []
    for transaction in transactions:
        amount, type, description, timestamp = transaction
        formatted_transactions.append({
            'amount': amount,
            'type': type,
            'description': description,
            'timestamp': timestamp
        })
    
    return jsonify({
        'status': 'success',
        'transactions': formatted_transactions
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

def get_task_cost(task_type='hcaptcha_basic'):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cost_key = 'basic_cost_per_1k' if task_type == 'hcaptcha_basic' else 'enterprise_cost_per_1k'
        cursor.execute("SELECT value FROM settings WHERE key = ?", (cost_key,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            # Default costs
            default_costs = {
                'hcaptcha_basic': 3.0,
                'enterprise': 5.0
            }
            return default_costs.get(task_type, 3.0) / 1000  # Cost per single solve
        
        # Convert from cost per 1k to cost per single solve
        return float(result[0]) / 1000
    except Exception as e:
        print(f"Error getting task cost: {e}")
        # Default costs per single solve
        default_costs = {
            'hcaptcha_basic': 0.003,
            'enterprise': 0.005
        }
        return default_costs.get(task_type, 0.003)

def increment_api_key_usage(api_key, task_type='hcaptcha_basic'):
    try:
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if usage tracking table exists, create it if not
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT,
            timestamp REAL,
            task_type TEXT,
            FOREIGN KEY (api_key) REFERENCES users(api_key)
        )
        ''')
        
        # Insert usage record
        cursor.execute(
            "INSERT INTO api_usage (api_key, timestamp, task_type) VALUES (?, ?, ?)",
            (api_key, time.time(), task_type)
        )
        
        # Get daily usage count for metrics
        day_ago = time.time() - 24*3600
        cursor.execute(
            "SELECT COUNT(*) FROM api_usage WHERE api_key = ? AND timestamp >= ?",
            (api_key, day_ago)
        )
        daily_count = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error incrementing API key usage: {e}")
        return False

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
            
            # Check if user has enough balance
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get user ID from API key
            cursor.execute("SELECT id FROM users WHERE api_key = ?", (self.api_key,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return False, "Invalid API key"
            
            user_id = user[0]
            
            # Get user's balance
            cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (user_id,))
            balance_result = cursor.fetchone()
            
            # Get task cost from settings based on task type
            task_cost = get_task_cost(task_type)
            
            if not balance_result or balance_result[0] < task_cost:
                conn.close()
                return False, "Insufficient balance"
            
            # Deduct balance
            new_balance = balance_result[0] - task_cost
            
            cursor.execute(
                "UPDATE balance SET amount = ?, last_updated = ? WHERE user_id = ?",
                (new_balance, time.time(), user_id)
            )
            
            # Add transaction record
            cursor.execute(
                "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, -task_cost, 'debit', f'Task: {task_type}', time.time())
            )
            
            # Generate a unique task ID
            task_id = str(uuid.uuid4())
            
            # Store in database
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
                
                # Increment API key usage on successful solve with task type
                increment_api_key_usage(self.api_key, task_type)
            
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
@csrf.exempt
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
@csrf.exempt
def get_result(task_id):
    # For GET requests, look for API key in query parameters
    api_key = request.args.get('key')
    
    # If not in query parameters, try JSON data (backwards compatibility)
    if not api_key and request.is_json:
        data = request.json
        if data and 'key' in data:
            api_key = data['key']
    
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

# Add the missing admin routes
@app.route('/admin_add_credits', methods=['POST'])
@admin_required
def admin_add_credits():
    user_id = request.form.get('user_id')
    amount = float(request.form.get('amount', 0))
    
    if not user_id or amount <= 0:
        flash('Invalid input', 'error')
        return redirect(url_for('admin_users'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get current balance
    cursor.execute("SELECT amount FROM balance WHERE user_id = ?", (user_id,))
    balance_result = cursor.fetchone()
    
    if not balance_result:
        # Create balance record if it doesn't exist
        cursor.execute(
            "INSERT INTO balance (user_id, amount, last_updated) VALUES (?, ?, ?)",
            (user_id, amount, time.time())
        )
        new_balance = amount
    else:
        # Update existing balance
        new_balance = balance_result[0] + amount
        cursor.execute(
            "UPDATE balance SET amount = ?, last_updated = ? WHERE user_id = ?",
            (new_balance, time.time(), user_id)
        )
    
    # Add transaction record
    cursor.execute(
        "INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, amount, 'credit', 'Admin credit', time.time())
    )
    
    conn.commit()
    conn.close()
    
    flash(f'Added {amount} credits to user {user_id}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin_reset_api_key', methods=['POST'])
@admin_required
def admin_reset_api_key():
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('Invalid user ID', 'error')
        return redirect(url_for('admin_users'))
    
    # Generate new API key as UUID (GUID)
    new_key = str(uuid.uuid4())
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user_id))
    conn.commit()
    conn.close()
    
    flash(f'API key reset for user {user_id}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin_delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('Invalid user ID', 'error')
        return redirect(url_for('admin_users'))
    
    # Prevent deleting yourself
    if int(user_id) == session.get('user_id'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Delete balance
    cursor.execute("DELETE FROM balance WHERE user_id = ?", (user_id,))
    
    # Delete transactions
    cursor.execute("DELETE FROM transactions WHERE user_id = ?", (user_id,))
    
    # Get API key to delete related tasks
    cursor.execute("SELECT api_key FROM users WHERE id = ?", (user_id,))
    api_key_result = cursor.fetchone()
    
    if api_key_result:
        # Delete tasks
        cursor.execute("DELETE FROM tasks WHERE api_key = ?", (api_key_result[0],))
    
    # Delete user
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'User {user_id} deleted successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin_update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    # Get form data
    allow_registration = 'allow_registration' in request.form
    require_captcha = 'require_captcha' in request.form
    enable_api = 'enable_api' in request.form
    default_credits = float(request.form.get('default_credits', 0))
    credit_cost = float(request.form.get('credit_cost', 0))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Update settings
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        ('allow_registration', str(int(allow_registration)), time.time())
    )
    
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        ('require_captcha', str(int(require_captcha)), time.time())
    )
    
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        ('enable_api', str(int(enable_api)), time.time())
    )
    
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        ('default_credits', str(default_credits), time.time())
    )
    
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        ('credit_cost', str(credit_cost), time.time())
    )
    
    conn.commit()
    conn.close()
    
    flash('Settings updated successfully', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin_backup_database', methods=['POST'])
@admin_required
def admin_backup_database():
    # This would typically create a database backup file
    # For simplicity, we'll just send a success message
    flash('Database backup functionality would be implemented here', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin_reset_settings', methods=['POST'])
@admin_required
def admin_reset_settings():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Reset to default settings
    default_settings = {
        'allow_registration': 1,
        'require_captcha': 1,
        'enable_api': 1,
        'default_credits': 0.0,
        'credit_cost': 0.003,
        'basic_cost_per_1k': 3.0,
        'enterprise_cost_per_1k': 5.0,
        'min_balance': 0.0
    }
    
    for key, value in default_settings.items():
        cursor.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, str(value), time.time())
        )
    
    conn.commit()
    conn.close()
    
    flash('Settings have been reset to defaults', 'success')
    return redirect(url_for('admin_settings'))

if __name__ == '__main__':
    # Enable debug mode only in development environments
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=80, debug=debug_mode) 