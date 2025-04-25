# hCaptcha Solver API

A simple HTTP API for solving hCaptcha challenges using the RazorCap service.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the API server:
```bash
python server.py
```

By default, the server will run on `http://0.0.0.0:80`.

## API Endpoints

### 1. Create Task

**Endpoint**: `/create_task`
**Method**: `POST`
**Description**: Creates a new captcha solving task.

**Request Body**:
```json
{
  "key": "your_razorcap_api_key",
  "type": "hcaptcha_basic",
  "data": {
    "sitekey": "hcaptcha_site_key",
    "siteurl": "discord.com",
    "proxy": "username:password@host:port",
    "rqdata": "optional_rqdata"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "task_id": "task_identifier"
}
```

### 2. Get Result

**Endpoint**: `/get_result/{task_id}`
**Method**: `GET`
**Request Body**:
```json
{
  "key": "your_razorcap_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "solution": "captcha_solution_token"
}
```

Or, if still solving:
```json
{
  "status": "solving"
}
```

## Additional API Endpoints

### 3. Get Balance

**Endpoint**: `/get_balance`
**Method**: `POST`
**Description**: Get current balance for your account.

**Request Body**:
```json
{
  "key": "your_razorcap_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "balance": 10.5
}
```

### 4. Get Daily Usage

**Endpoint**: `/get_daily_usage`
**Method**: `POST`
**Description**: Get number of requests in the last 24 hours.

**Request Body**:
```json
{
  "key": "your_razorcap_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "daily_requests": 150
}
```

### 5. Get Success Rate

**Endpoint**: `/get_success_rate`
**Method**: `POST`
**Description**: Get your success rate for solved captchas.

**Request Body**:
```json
{
  "key": "your_razorcap_api_key"
}
```

**Response**:
```json
{
  "status": "success",
  "success_rate": 95.5
}
```

## Example Usage with Python

```python
import requests
import time
import json

API_URL = "http://localhost:5000"
API_KEY = "your_razorcap_api_key"

# Create a task
response = requests.post(f"{API_URL}/create_task", json={
    "key": API_KEY,
    "type": "hcaptcha_basic",
    "data": {
        "sitekey": "4c672d35-0701-42b2-88c3-78380b0db560",
        "siteurl": "discord.com",
        "proxy": "username:password@host:port"
    }
})

task_data = response.json()
if task_data["status"] == "success":
    task_id = task_data["task_id"]
    
    # Poll for result
    while True:
        result_response = requests.get(
            f"{API_URL}/get_result/{task_id}", 
            json={"key": API_KEY}
        )
        result = result_response.json()
        
        if result["status"] == "success":
            print(f"Solved: {result['solution']}")
            break
        elif result["status"] == "error":
            print(f"Error: {result['message']}")
            break
        
        print("Still solving...")
        time.sleep(1)
```

## Notes

- You need a valid RazorCap API key to use this service
- Always provide a proxy in the correct format (username:password@host:port)
- Discord captchas typically use sitekey: '4c672d35-0701-42b2-88c3-78380b0db560'
- Pricing is based on your account tier (basic or enterprise) 