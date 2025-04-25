# hCaptcha Solver API

A simple HTTP API for solving hCaptcha challenges using the RazorCap service.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the API server:
```bash
python api.py
```

By default, the server will run on `http://0.0.0.0:5000`.

## API Endpoints

### 1. Solve Captcha

**Endpoint**: `/solve`
**Method**: `POST`
**Description**: Solves an hCaptcha challenge from start to finish.

**Request Body**:
```json
{
  "api_key": "your_razorcap_api_key",
  "site_key": "hcaptcha_site_key",
  "proxy": "username:password@host:port",
  "rqdata": "optional_rqdata"
}
```

**Response**:
```json
{
  "status": "success",
  "solution": "captcha_solution_token"
}
```

### 2. Create Task

**Endpoint**: `/create_task`
**Method**: `POST`
**Description**: Creates a new captcha solving task.

**Request Body**:
```json
{
  "api_key": "your_razorcap_api_key",
  "site_key": "hcaptcha_site_key",
  "proxy": "username:password@host:port",
  "rqdata": "optional_rqdata"
}
```

**Response**:
```json
{
  "status": "success",
  "task_id": "task_identifier"
}
```

### 3. Get Result

**Endpoint**: `/get_result/{task_id}`
**Method**: `GET`
**Parameters**:
- `task_id`: The ID of the task to check
- `api_key`: Your RazorCap API key (as a query parameter)

**Response**:
```json
{
  "status": "solved",
  "solution": "captcha_solution_token"
}
```

Or, if still solving:
```json
{
  "status": "solving"
}
```

## Example Usage with Python

```python
import requests

API_URL = "http://localhost:5000"
API_KEY = "your_razorcap_api_key"

# Solve captcha directly
response = requests.post(f"{API_URL}/solve", json={
    "api_key": API_KEY,
    "site_key": "4c672d35-0701-42b2-88c3-78380b0db560",
    "proxy": "username:password@host:port"
})
print(response.json())

# Or create a task and poll for result
task_response = requests.post(f"{API_URL}/create_task", json={
    "api_key": API_KEY,
    "site_key": "4c672d35-0701-42b2-88c3-78380b0db560",
    "proxy": "username:password@host:port"
})

task_id = task_response.json()["task_id"]

# Poll for result
import time
while True:
    result_response = requests.get(f"{API_URL}/get_result/{task_id}?api_key={API_KEY}")
    result = result_response.json()
    
    if result["status"] == "solved":
        print(f"Solved: {result['solution']}")
        break
    
    print("Still solving...")
    time.sleep(1)
```

## Notes

- You need a valid RazorCap API key to use this service
- Always provide a proxy in the correct format (username:password@host:port)
- Discord captchas typically use sitekey: '4c672d35-0701-42b2-88c3-78380b0db560' 