import os

# Database configuration
DATABASE_FILE = os.getenv('DATABASE_FILE', 'phonebook.db')

# Security configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# User roles
ROLE_READ = "read"
ROLE_READWRITE = "readwrite"

# Logging configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
AUDIT_LOG_FILE = "audit.log" 