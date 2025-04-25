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

## Notes

- You need a valid RazorCap API key to use this service
- Always provide a proxy in the correct format (username:password@host:port)
- Discord captchas typically use sitekey: '4c672d35-0701-42b2-88c3-78380b0db560' 
