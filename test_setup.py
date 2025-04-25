import os
import sqlite3
from main import init_db

def setup_test_environment():
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data/backups', exist_ok=True)
    
    # Set environment variables
    os.environ['DATABASE_FILE'] = 'test_phonebook.db'
    os.environ['AUDIT_LOG_FILE'] = 'logs/audit.log'
    
    # Initialize the test database
    init_db()

if __name__ == "__main__":
    setup_test_environment()
    print("Test environment setup complete!") 