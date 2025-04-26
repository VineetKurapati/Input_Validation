import pytest
from fastapi.testclient import TestClient
from main import app, init_db, get_db, get_password_hash
import sqlite3
import os

# Set test database path
os.environ['DATABASE_FILE'] = 'test_phonebook.db'

# Initialize test client
client = TestClient(app)

# Test data
VALID_NAMES = [
    "Bruce Schneier",
    "Schneier, Bruce",
    "Schneier, Bruce Wayne",
    "O'Malley, John F.",
    "John O'Malley-Smith",
    "Cher"
]

INVALID_NAMES = [
    "Ron O''Henry",
    "Ron O'Henry-Smith-Barnes",
    "L33t Hacker",
    "<Script>alert('XSS')</Script>",
    "Brad Everett Samuel Smith",
    "select * from users;"
]

VALID_PHONES = [
    "12345",
    "(703)111-2121",
    "123-1234",
    "+1(703)111-2121",
    "+32 (21) 212-2324",
    "1(703)123-1234",
    "011 701 111 1234",
    "12345.12345",
    "011 1 703 111 1234"
]

INVALID_PHONES = [
    "123",
    "1/703/123/1234",
    "Nr 102-123-1234",
    "<script>alert('XSS')</script>",
    "7031111234",
    "+1234 (201) 123-1234",
    "(001) 123-1234",
    "+01 (703) 123-1234",
    "(703) 123-1234 ext 204"
]

# SQL Injection test cases
SQL_INJECTION_ATTEMPTS = [
    "Robert'); DROP TABLE phonebook; --",
    "Robert'); DELETE FROM users; --",
    "Robert'); UPDATE users SET role='readwrite' WHERE username='reader'; --",
    "1' OR '1'='1",
    "1' UNION SELECT username, password FROM users; --"
]

# XSS test cases
XSS_ATTEMPTS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
    "\"onmouseover=\"alert('XSS')"
]

def get_token(username: str, password: str):
    """Get authentication token for a user."""
    # Ensure database is initialized
    init_db()
    
    response = client.post(
        "/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture(autouse=True)
def setup_teardown():
    """Setup and teardown for all tests."""
    # Setup
    init_db()
    yield
    # Teardown
    if os.path.exists('test_phonebook.db'):
        os.remove('test_phonebook.db')

@pytest.fixture
def test_db():
    """Test database fixture."""
    yield

def test_login(test_db):
    # Test valid login
    response = client.post(
        "/token",
        data={"username": "reader", "password": "readerpass"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    
    # Test invalid login
    response = client.post(
        "/token",
        data={"username": "reader", "password": "wrongpass"}
    )
    assert response.status_code == 401

def test_list_entries(test_db):
    # Test without authentication
    response = client.get("/PhoneBook/list")
    assert response.status_code == 401
    
    # Test with read role
    token = get_token("reader", "readerpass")
    response = client.get(
        "/PhoneBook/list",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == []

def test_add_entry(test_db):
    token = get_token("writer", "writerpass")
    
    # Test valid entries
    for name, phone in zip(VALID_NAMES, VALID_PHONES[:len(VALID_NAMES)]):
        print(f"Testing name: {name}, phone: {phone}")  # Debug print
        response = client.post(
            "/PhoneBook/add",
            json={"name": name, "phoneNumber": phone},
            headers={"Authorization": f"Bearer {token}"}
        )
        print(f"Response status: {response.status_code}")  # Debug print
        if response.status_code != 200:
            print(f"Response body: {response.json()}")  # Debug print
        assert response.status_code == 200
    
    # Test invalid names
    for name in INVALID_NAMES:
        response = client.post(
            "/PhoneBook/add",
            json={"name": name, "phoneNumber": VALID_PHONES[0]},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
    
    # Test invalid phones - use unique names for each test
    for i, phone in enumerate(INVALID_PHONES):
        unique_name = f"Test User {i}"  # Generate unique name for each test
        response = client.post(
            "/PhoneBook/add",
            json={"name": unique_name, "phoneNumber": phone},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
    
    # Test duplicate entry
    response = client.post(
        "/PhoneBook/add",
        json={"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 409

def test_delete_by_name(test_db):
    token = get_token("writer", "writerpass")
    
    # Add an entry first
    client.post(
        "/PhoneBook/add",
        json={"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Test successful deletion
    response = client.put(
        f"/PhoneBook/deleteByName?name={VALID_NAMES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Test non-existent entry
    response = client.put(
        f"/PhoneBook/deleteByName?name={VALID_NAMES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 404

def test_delete_by_number(test_db):
    token = get_token("writer", "writerpass")
    
    # Add an entry first
    client.post(
        "/PhoneBook/add",
        json={"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Test successful deletion
    response = client.put(
        f"/PhoneBook/deleteByNumber?number={VALID_PHONES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Test non-existent entry
    response = client.put(
        f"/PhoneBook/deleteByNumber?number={VALID_PHONES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 404

def test_authorization(test_db):
    # Test read-only user trying to add entry
    token = get_token("reader", "readerpass")
    response = client.post(
        "/PhoneBook/add",
        json={"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    
    # Test read-only user trying to delete entry
    response = client.put(
        f"/PhoneBook/deleteByName?name={VALID_NAMES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403

def test_audit_logging(test_db):
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    token = get_token("writer", "writerpass")
    
    # Perform some operations
    client.post(
        "/PhoneBook/add",
        json={"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    client.get(
        "/PhoneBook/list",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    client.put(
        f"/PhoneBook/deleteByName?name={VALID_NAMES[0]}",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Check if audit.log exists and has entries
    assert os.path.exists("logs/audit.log")
    with open("logs/audit.log", "r") as f:
        log_content = f.read()
        assert "added entry:" in log_content.lower()
        assert "deleted entry by name:" in log_content.lower()
        # The list operation doesn't have a log message, so we'll check for the HTTP request
        assert "get http://testserver/phonebook/list" in log_content.lower()

def test_sql_injection(test_db):
    token = get_token("writer", "writerpass")
    
    # Test SQL injection attempts in name field
    for injection in SQL_INJECTION_ATTEMPTS:
        response = client.post(
            "/PhoneBook/add",
            json={"name": injection, "phoneNumber": VALID_PHONES[0]},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400, f"SQL injection attempt should fail: {injection}"
        
        # Verify the database is still intact
        response = client.get(
            "/PhoneBook/list",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200, "Database should still be accessible"

def test_xss_attempts(test_db):
    token = get_token("writer", "writerpass")
    
    # Test XSS attempts in name field
    for xss in XSS_ATTEMPTS:
        response = client.post(
            "/PhoneBook/add",
            json={"name": xss, "phoneNumber": VALID_PHONES[0]},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400, f"XSS attempt should fail: {xss}"

def test_token_expiration():
    # Get initial token
    response = client.post(
        "/token",
        data={"username": "reader", "password": "readerpass"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    # Wait for token to expire (if we had shorter expiration for testing)
    # time.sleep(ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    
    # Try to use expired token (simulated by modifying the token)
    invalid_token = token[:-10] + "x" * 10  # Corrupt the token
    response = client.get(
        "/PhoneBook/list",
        headers={"Authorization": f"Bearer {invalid_token}"}
    )
    assert response.status_code == 401, "Expired/invalid token should be rejected"

def test_authorization_boundaries():
    # Get reader token
    reader_token = get_token("reader", "readerpass")
    
    # Try to access write operations with reader token
    write_operations = [
        ("POST", "/PhoneBook/add", {"name": VALID_NAMES[0], "phoneNumber": VALID_PHONES[0]}),
        ("PUT", f"/PhoneBook/deleteByName?name={VALID_NAMES[0]}", None),
        ("PUT", f"/PhoneBook/deleteByNumber?number={VALID_PHONES[0]}", None)
    ]
    
    for method, endpoint, data in write_operations:
        response = client.request(
            method,
            endpoint,
            json=data,
            headers={"Authorization": f"Bearer {reader_token}"}
        )
        assert response.status_code == 403, f"Reader should not have access to {method} {endpoint}" 