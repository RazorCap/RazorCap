from flask import Flask, request, jsonify
from time import sleep
from core.solver import Hcaptcha
import threading
import sqlite3
import uuid
import time
import json
import os

app = Flask(__name__)

# Set up SQLite database
TASKS_DB_PATH = "tasks.db"
KEYS_DB_PATH = "api_keys.db"

def init_db():
    # Initialize tasks database
    conn = sqlite3.connect(TASKS_DB_PATH)
    cursor = conn.cursor()
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

def validate_api_key(api_key):
    try:
        conn = sqlite3.connect(KEYS_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT is_active, usage_limit, usage_count, expires_at FROM api_keys WHERE key = ?", (api_key,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, "Invalid API key"
        
        is_active, usage_limit, usage_count, expires_at = result
        
        if not is_active:
            return False, "API key is inactive"
        
        if expires_at and time.time() > expires_at:
            return False, "API key has expired"
        
        if usage_limit and usage_count >= usage_limit:
            return False, "API key usage limit exceeded"
        
        return True, "Valid API key"
    except Exception as e:
        return False, str(e)

def increment_api_key_usage(api_key):
    try:
        conn = sqlite3.connect(KEYS_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET usage_count = usage_count + 1 WHERE key = ?", (api_key,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error incrementing API key usage: {e}")
        return False

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
            conn = sqlite3.connect(TASKS_DB_PATH)
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
            conn = sqlite3.connect(TASKS_DB_PATH)
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
            conn = sqlite3.connect(TASKS_DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE tasks SET status = ?, error = ? WHERE task_id = ?", 
                ("error", str(e), task_id)
            )
            conn.commit()
            conn.close()
    
    def get_task_solution(self, task_id):
        try:
            conn = sqlite3.connect(TASKS_DB_PATH)
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

@app.route('/solve', methods=['POST'])
def solve_captcha():
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
    result = solver.solve(sitekey, siteurl, proxy, rqdata)
    
    if result.startswith('error'):
        error_message = "Failed to solve captcha"
        if "_" in result:
            error_message = result.split("_", 1)[1]
        return jsonify({"status": "error", "message": error_message}), 500
    
    return jsonify({"status": "success", "solution": result})

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
    result = solver.create_task(task_type, sitekey, siteurl, proxy, rqdata)
    
    if not result[0]:
        return jsonify({"status": "error", "message": result[1]}), 500
    
    return jsonify({"status": "success", "task_id": result[1]})

@app.route('/get_result/<task_id>', methods=['GET'])
def get_result(task_id):
    api_key = request.args.get('key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    solver = Solver(api_key)
    result = solver.get_task_solution(task_id)
    
    if result[0] == 'unauthorized':
        return jsonify({"status": "error", "message": "Unauthorized access to this task"}), 403
    elif result[0] == 'solved':
        return jsonify({"status": "solved", "solution": result[1]})
    else:
        return jsonify({"status": result[0]})

@app.route('/get_task_result', methods=['POST'])
def get_task_result():
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    task_id = data.get('task_id')
    if not task_id:
        return jsonify({"status": "error", "message": "Task ID is required"}), 400
    
    solver = Solver(api_key)
    result = solver.get_task_solution(task_id)
    
    if result[0] == 'unauthorized':
        return jsonify({"status": "error", "message": "Unauthorized access to this task"}), 403
    elif result[0] == 'solved':
        return jsonify({"status": "solved", "solution": result[1]})
    else:
        return jsonify({"status": result[0]})

def cleanup_tasks():
    while True:
        try:
            current_time = time.time()
            
            conn = sqlite3.connect(TASKS_DB_PATH)
            cursor = conn.cursor()
            
            # Delete tasks older than 30 minutes
            cursor.execute("DELETE FROM tasks WHERE created_at < ?", (current_time - 1800,))
            
            conn.commit()
            conn.close()
            
            # Sleep for 5 minutes
            sleep(300)
        except Exception as e:
            print(f"Error cleaning up tasks: {e}")
            sleep(300)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_tasks)
    cleanup_thread.daemon = True
    cleanup_thread.start()
    
    app.run(host='0.0.0.0', port=5000) 