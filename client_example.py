import requests
import time

# Configuration
API_URL = "http://localhost:5000"
API_KEY = "your_razorcap_api_key"  # Replace with your actual API key
SITE_KEY = "4c672d35-0701-42b2-88c3-78380b0db560"  # Default Discord sitekey
PROXY = "user:pass@host:port"  # Replace with your actual proxy

def solve_directly():
    """Solve captcha in a single request"""
    print("Solving captcha directly...")
    
    response = requests.post(f"{API_URL}/solve", json={
        "api_key": API_KEY,
        "site_key": SITE_KEY,
        "proxy": PROXY
    })
    
    if response.status_code == 200:
        result = response.json()
        if result["status"] == "success":
            print(f"Captcha solved successfully!")
            print(f"Solution: {result['solution']}")
            return result['solution']
        else:
            print(f"Failed to solve: {result.get('message', 'Unknown error')}")
    else:
        print(f"Request failed with status code: {response.status_code}")
    
    return None

def solve_with_polling():
    """Create a task and poll for the result"""
    print("Creating captcha solving task...")
    
    # Create task
    task_response = requests.post(f"{API_URL}/create_task", json={
        "api_key": API_KEY,
        "site_key": SITE_KEY,
        "proxy": PROXY
    })
    
    if task_response.status_code != 200:
        print(f"Failed to create task: {task_response.status_code}")
        return None
    
    task_result = task_response.json()
    if task_result["status"] != "success":
        print(f"Failed to create task: {task_result.get('message', 'Unknown error')}")
        return None
    
    task_id = task_result["task_id"]
    print(f"Task created with ID: {task_id}")
    
    # Poll for result
    attempts = 0
    while attempts < 30:  # Limit to 30 attempts (15 seconds)
        print(f"Checking status... (attempt {attempts+1})")
        
        result_response = requests.get(f"{API_URL}/get_result/{task_id}?api_key={API_KEY}")
        
        if result_response.status_code != 200:
            print(f"Failed to get result: {result_response.status_code}")
            return None
        
        result = result_response.json()
        
        if result["status"] == "solved":
            print(f"Captcha solved successfully!")
            print(f"Solution: {result['solution']}")
            return result['solution']
        
        print(f"Status: {result['status']}")
        time.sleep(0.5)
        attempts += 1
    
    print("Timed out waiting for solution")
    return None

if __name__ == "__main__":
    print("=== hCaptcha Solver Client Example ===")
    print("1. Solve directly")
    print("2. Solve with polling")
    
    choice = input("Choose an option (1 or 2): ")
    
    if choice == "1":
        solution = solve_directly()
    elif choice == "2":
        solution = solve_with_polling()
    else:
        print("Invalid choice")
        solution = None
    
    if solution:
        print("\nFinal captcha token:")
        print(solution) 