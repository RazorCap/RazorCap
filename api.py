from flask import Flask, request, jsonify
from time import sleep

app = Flask(__name__)

@app.route('/solve', methods=['POST'])
def solve_captcha():
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    proxy = data.get('proxy', '')
    site_key = data.get('site_key')
    if not site_key:
        return jsonify({"status": "error", "message": "Site key is required"}), 400
    
    rqdata = data.get('rqdata')
    
    solver = Solver(api_key)
    result = solver.solve(proxy, site_key, rqdata)
    
    if result == 'error':
        return jsonify({"status": "error", "message": "Failed to solve captcha"}), 500
    
    return jsonify({"status": "success", "solution": result})

@app.route('/create_task', methods=['POST'])
def create_task():
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    proxy = data.get('proxy', '')
    site_key = data.get('site_key')
    if not site_key:
        return jsonify({"status": "error", "message": "Site key is required"}), 400
    
    rqdata = data.get('rqdata')
    
    solver = Solver(api_key)
    result = solver.create_task(proxy, site_key, rqdata)
    
    if not result[0]:
        return jsonify({"status": "error", "message": result[1]}), 500
    
    return jsonify({"status": "success", "task_id": result[1]})

@app.route('/get_result/<task_id>', methods=['GET'])
def get_result(task_id):
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    solver = Solver(api_key)
    result = solver.get_task_solution(task_id)
    
    if result[0] == 'solved':
        return jsonify({"status": "solved", "solution": result[1]})
    else:
        return jsonify({"status": result[0]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=666) 