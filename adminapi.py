from flask import Flask, request, jsonify, render_template
import sqlite3
import secrets
import time
import os

app = Flask(__name__)

# Set up SQLite database
DB_PATH = "api_keys.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        name TEXT,
        email TEXT,
        key TEXT UNIQUE,
        usage_limit INTEGER,
        usage_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT 1,
        created_at REAL,
        expires_at REAL
    )
    ''')
    conn.commit()
    conn.close()

def generate_api_key():
    return secrets.token_hex(16)

@app.route('/admin/dashboard')
def dashboard():
    # In a real implementation, you'd have proper authentication
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key_id, name, email, key, usage_limit, usage_count, is_active, created_at, expires_at FROM api_keys ORDER BY created_at DESC")
    keys = cursor.fetchall()
    conn.close()
    
    keys_data = []
    for key in keys:
        key_id, name, email, api_key, usage_limit, usage_count, is_active, created_at, expires_at = key
        keys_data.append({
            "key_id": key_id,
            "name": name,
            "email": email,
            "key": api_key,
            "usage_limit": usage_limit,
            "usage_count": usage_count,
            "is_active": bool(is_active),
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(created_at)),
            "expires_at": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at)) if expires_at else "Never"
        })
    
    return render_template('dashboard.html', keys=keys_data)

@app.route('/admin/keys', methods=['GET'])
def list_keys():
    # In a real implementation, you'd have proper authentication
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key_id, name, email, key, usage_limit, usage_count, is_active, created_at, expires_at FROM api_keys")
    keys = cursor.fetchall()
    conn.close()
    
    keys_data = []
    for key in keys:
        key_id, name, email, api_key, usage_limit, usage_count, is_active, created_at, expires_at = key
        keys_data.append({
            "key_id": key_id,
            "name": name,
            "email": email,
            "key": api_key,
            "usage_limit": usage_limit,
            "usage_count": usage_count,
            "is_active": bool(is_active),
            "created_at": created_at,
            "expires_at": expires_at
        })
    
    return jsonify({"status": "success", "keys": keys_data})

@app.route('/admin/add_key', methods=['POST'])
def add_key():
    # In a real implementation, you'd have proper authentication
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    name = data.get('name')
    email = data.get('email')
    
    if not name or not email:
        return jsonify({"status": "error", "message": "Name and email are required"}), 400
    
    # Generate a new API key
    api_key = generate_api_key()
    usage_limit = data.get('usage_limit', 100)
    
    # Calculate expiration (30 days from now by default)
    expires_at = data.get('expires_at', time.time() + (30 * 24 * 60 * 60))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO api_keys 
        (key_id, name, email, key, usage_limit, usage_count, is_active, created_at, expires_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            secrets.token_hex(8),
            name,
            email,
            api_key,
            usage_limit,
            0,
            1,
            time.time(),
            expires_at
        ))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success", 
            "message": "API key created successfully",
            "key": api_key
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/deactivate_key/<key_id>', methods=['POST'])
def deactivate_key(key_id):
    # In a real implementation, you'd have proper authentication
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ?", (key_id,))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success", 
            "message": "API key deactivated successfully"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/activate_key/<key_id>', methods=['POST'])
def activate_key(key_id):
    # In a real implementation, you'd have proper authentication
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET is_active = 1 WHERE key_id = ?", (key_id,))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success", 
            "message": "API key activated successfully"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/delete_key/<key_id>', methods=['POST'])
def delete_key(key_id):
    # In a real implementation, you'd have proper authentication
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success", 
            "message": "API key deleted successfully"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/validate_key', methods=['POST'])
def validate_key():
    data = request.json
    
    if not data or 'key' not in data:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    api_key = data.get('key')
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT is_active, usage_limit, usage_count, expires_at FROM api_keys WHERE key = ?", (api_key,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"status": "error", "message": "Invalid API key"}), 404
        
        is_active, usage_limit, usage_count, expires_at = result
        
        if not is_active:
            return jsonify({"status": "error", "message": "API key is inactive"}), 403
        
        if expires_at and time.time() > expires_at:
            return jsonify({"status": "error", "message": "API key has expired"}), 403
        
        if usage_limit and usage_count >= usage_limit:
            return jsonify({"status": "error", "message": "API key usage limit exceeded"}), 403
        
        return jsonify({
            "status": "success", 
            "message": "API key is valid",
            "usage": {
                "used": usage_count,
                "limit": usage_limit,
                "remaining": usage_limit - usage_count if usage_limit else "unlimited"
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/admin/increment_usage', methods=['POST'])
def increment_usage():
    data = request.json
    
    if not data or 'key' not in data:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    api_key = data.get('key')
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE api_keys SET usage_count = usage_count + 1 WHERE key = ?", (api_key,))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success", 
            "message": "API key usage incremented"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create a simple dashboard HTML template
    with open('templates/dashboard.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>RazorCap API Key Management</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .btn {
            display: inline-block;
            padding: 8px 12px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }
        .btn-red {
            background-color: #f44336;
        }
        .btn-blue {
            background-color: #2196F3;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input, select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>RazorCap API Key Management</h1>
        
        <div class="card">
            <h2>Add New API Key</h2>
            <form id="addKeyForm">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="usageLimit">Usage Limit:</label>
                    <input type="number" id="usageLimit" name="usageLimit" value="100">
                </div>
                <button type="submit" class="btn">Add API Key</button>
            </form>
        </div>
        
        <div class="card">
            <h2>API Keys</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>API Key</th>
                        <th>Usage</th>
                        <th>Created</th>
                        <th>Expires</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for key in keys %}
                    <tr>
                        <td>{{ key.name }}</td>
                        <td>{{ key.email }}</td>
                        <td>{{ key.key }}</td>
                        <td>{{ key.usage_count }} / {% if key.usage_limit %}{{ key.usage_limit }}{% else %}∞{% endif %}</td>
                        <td>{{ key.created_at }}</td>
                        <td>{{ key.expires_at }}</td>
                        <td>{% if key.is_active %}Active{% else %}Inactive{% endif %}</td>
                        <td>
                            {% if key.is_active %}
                            <button class="btn btn-red deactivate-btn" data-id="{{ key.key_id }}">Deactivate</button>
                            {% else %}
                            <button class="btn btn-blue activate-btn" data-id="{{ key.key_id }}">Activate</button>
                            {% endif %}
                            <button class="btn btn-red delete-btn" data-id="{{ key.key_id }}">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        document.getElementById('addKeyForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const usageLimit = document.getElementById('usageLimit').value;
            
            fetch('/admin/add_key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    email: email,
                    usage_limit: parseInt(usageLimit)
                }),
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert('API Key created: ' + data.key);
                    location.reload();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        });
        
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('deactivate-btn')) {
                const keyId = e.target.getAttribute('data-id');
                
                fetch('/admin/deactivate_key/' + keyId, {
                    method: 'POST',
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error: ' + error);
                });
            }
            
            if (e.target.classList.contains('activate-btn')) {
                const keyId = e.target.getAttribute('data-id');
                
                fetch('/admin/activate_key/' + keyId, {
                    method: 'POST',
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => {
                    alert('Error: ' + error);
                });
            }
            
            if (e.target.classList.contains('delete-btn')) {
                if (confirm('Are you sure you want to delete this API key?')) {
                    const keyId = e.target.getAttribute('data-id');
                    
                    fetch('/admin/delete_key/' + keyId, {
                        method: 'POST',
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            location.reload();
                        } else {
                            alert('Error: ' + data.message);
                        }
                    })
                    .catch(error => {
                        alert('Error: ' + error);
                    });
                }
            }
        });
    </script>
</body>
</html>
        ''')
    
    app.run(host='0.0.0.0', port=5001) 