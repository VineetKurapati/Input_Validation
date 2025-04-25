from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
import re
from datetime import datetime, timedelta
from datetime import timezone
from typing import List, Optional
import sqlite3
import os
import logging
from jose import JWTError, jwt
from passlib.context import CryptContext
import json
from contextlib import asynccontextmanager
from config import *  # Import configuration

# Security configuration
# Use SECRET_KEY from config.py
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configure logging
logging.basicConfig(
    filename=AUDIT_LOG_FILE,
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    force=True
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database models
class User(BaseModel):
    username: str
    role: str  # "read" or "readwrite"

class UserInDB(User):
    hashed_password: str

class PhoneBookEntry(BaseModel):
    name: str
    phone_number: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, name: str) -> str:
        """
        Validate name format:
        - Must start with a letter
        - Can contain letters, spaces, single apostrophes, and single hyphens
        - Can have an optional comma followed by more name parts
        - No numbers or special characters except apostrophes and hyphens
        - No multiple consecutive apostrophes or hyphens
        - No more than 3 name parts (e.g. "First Middle Last" or "Last, First Middle")
        """
        # Check for multiple apostrophes or hyphens
        if name.count("'") > 1 or name.count("-") > 1:
            logging.error(f"Invalid name format: {name} - multiple apostrophes or hyphens")
            raise ValueError('Invalid name format: multiple apostrophes or hyphens')
            
        # Check for numbers or special characters
        if any(c.isdigit() for c in name) or any(c in "!@#$%^&*()_+=[]{}|\\:;\"<>?/" for c in name):
            logging.error(f"Invalid name format: {name} - contains numbers or special characters")
            raise ValueError('Invalid name format: contains numbers or special characters')
            
        # Check for multiple consecutive spaces
        if "  " in name:
            logging.error(f"Invalid name format: {name} - multiple consecutive spaces")
            raise ValueError('Invalid name format: multiple consecutive spaces')
            
        # Check for more than 3 name parts
        name_parts = [part.strip() for part in name.replace(",", " ").split()]
        if len(name_parts) > 3:
            logging.error(f"Invalid name format: {name} - more than 3 name parts")
            raise ValueError('Invalid name format: more than 3 name parts')
            
        # Check basic pattern
        pattern = r"^[A-Za-z]+(?:[\s\'-][A-Za-z]+)*(?:,\s*[A-Za-z]+(?:[\s\'-][A-Za-z]+)*(?:\s+[A-Z]\.)?)?$"
        if not re.match(pattern, name):
            logging.error(f"Invalid name format: {name}")
            logging.error(f"Pattern: {pattern}")
            logging.error(f"Match result: {re.match(pattern, name)}")
            raise ValueError('Invalid name format: does not match required pattern')
            
        return name

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v):
        # Phone number regex pattern - handle all valid cases
        # Examples:
        # - "12345"
        # - "(703)111-2121"
        # - "123-1234"
        # - "+1(703)111-2121"
        # - "+32 (21) 212-2324"
        # - "1(703)123-1234"
        # - "011 701 111 1234"
        # - "12345.12345"
        # - "011 1 703 111 1234"
        phone_pattern = r'^\+?(\d{1,3}[-.\s]?)?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}$'
        if not re.match(phone_pattern, v):
            logging.error(f"Invalid phone number format: {v}")
            logging.error(f"Pattern: {phone_pattern}")
            logging.error(f"Match result: {re.match(phone_pattern, v)}")
            raise ValueError('Invalid phone number format')
        return v

# Database functions
def init_db():
    """Initialize the database with required tables and test users."""
    try:
        # Get database file path from environment or use default
        db_file = os.getenv('DATABASE_FILE', DATABASE_FILE)
        
        # Create database directory if it doesn't exist
        db_dir = os.path.dirname(db_file)
        if db_dir:  # Only create directory if path has a directory component
            os.makedirs(db_dir, exist_ok=True)
        
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
        
        logging.info(f"Database initialized successfully at {db_file}")
        
    except Exception as e:
        logging.error(f"Error initializing database: {str(e)}")
        raise

def get_db():
    db_file = os.getenv('DATABASE_FILE', DATABASE_FILE)
    conn = sqlite3.connect(db_file)
    return conn

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    """Get user from database by username."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT username, hashed_password, role FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user:
            return UserInDB(username=user[0], hashed_password=user[1], role=user[2])
        return None
    except Exception as e:
        logging.error(f"Error getting user {username}: {str(e)}")
        return None

def authenticate_user(username: str, password: str):
    """Authenticate user with username and password."""
    try:
        user = get_user(username)
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user
    except Exception as e:
        logging.error(f"Error authenticating user {username}: {str(e)}")
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await startup_event()
    yield
    # Shutdown
    # Don't remove the database file on shutdown

app = FastAPI(title="Phone Book API", version="1.0.0", lifespan=lifespan)

@app.on_event("startup")
async def startup_event():
    try:
        init_db()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize database: {str(e)}")
        raise

# API endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/PhoneBook/list", response_model=List[PhoneBookEntry])
async def list_entries(current_user: User = Depends(get_current_active_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM phonebook")
    entries = [PhoneBookEntry(name=row[0], phone_number=row[1]) for row in c.fetchall()]
    conn.close()
    return entries

@app.post("/PhoneBook/add")
async def add_entry(entry: PhoneBookEntry, current_user: User = Depends(get_current_active_user)):
    if current_user.role != ROLE_READWRITE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO phonebook (name, phone_number) VALUES (?, ?)",
                 (entry.name, entry.phone_number))
        conn.commit()
        logging.info(f"Added entry: {entry.name} - {entry.phone_number}")
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Entry already exists"
        )
    finally:
        conn.close()
    return {"message": "Entry added successfully"}

@app.put("/PhoneBook/deleteByName")
async def delete_by_name(name: str, current_user: User = Depends(get_current_active_user)):
    if current_user.role != ROLE_READWRITE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    conn = get_db()
    try:
        c = conn.cursor()
        # Use parameterized query
        c.execute("DELETE FROM phonebook WHERE name = ?", (name,))
        if c.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found"
            )
        conn.commit()
        logging.info(f"Deleted entry by name: {name}")
        return {"message": "Entry deleted successfully"}
    except Exception as e:
        conn.rollback()
        logging.error(f"Error deleting entry by name {name}: {str(e)}")
        raise
    finally:
        conn.close()

@app.put("/PhoneBook/deleteByNumber")
async def delete_by_number(phone_number: str, current_user: User = Depends(get_current_active_user)):
    if current_user.role != ROLE_READWRITE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    conn = get_db()
    try:
        c = conn.cursor()
        # Use parameterized query
        c.execute("DELETE FROM phonebook WHERE phone_number = ?", (phone_number,))
        if c.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found"
            )
        conn.commit()
        logging.info(f"Deleted entry by number: {phone_number}")
        return {"message": "Entry deleted successfully"}
    except Exception as e:
        conn.rollback()
        logging.error(f"Error deleting entry by number {phone_number}: {str(e)}")
        raise
    finally:
        conn.close() 