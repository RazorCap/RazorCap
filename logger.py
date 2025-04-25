import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class Logger:
    def __init__(self):
        self.logger = logging.getLogger("hcaptcha_solver")
    
    def info(self, message, start_time=None, end_time=None):
        if start_time and end_time:
            elapsed = round(end_time - start_time, 2)
            self.logger.info(f"{message} [took {elapsed}s]")
        else:
            self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def debug(self, message):
        self.logger.debug(message)

# Create a logger instance
logger = Logger() 