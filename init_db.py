import sqlite3
import os
from passlib.context import CryptContext
from config import *

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def init_db():
    """Initialize the database with required tables and test users."""
    try:
        # Get database file path from environment or use default
        db_file = os.getenv('DATABASE_FILE', DATABASE_FILE)
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Drop existing tables to ensure clean state
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('DROP TABLE IF EXISTS phonebook')

        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')

        # Create phonebook table
        cursor.execute('''
            CREATE TABLE phonebook (
                name TEXT PRIMARY KEY,
                phone_number TEXT NOT NULL
            )
        ''')

        # Add test users with proper hashed passwords
        test_users = [
            ('reader', pwd_context.hash('readerpass'), ROLE_READ),
            ('writer', pwd_context.hash('writerpass'), ROLE_READWRITE)
        ]

        for username, hashed_password, role in test_users:
            cursor.execute(
                'INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)',
                (username, hashed_password, role)
            )

        conn.commit()
        conn.close()
        
        print(f"Database initialized successfully at {db_file}")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

if __name__ == "__main__":
    init_db() 