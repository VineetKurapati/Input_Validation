# PhoneBook API

A secure and scalable phonebook API built with FastAPI, featuring authentication, rate limiting, and database backup functionality.

## Features

- 🔐 Secure authentication with JWT tokens
- 👥 Role-based access control (reader/writer)
- 📱 Phone number validation
- 📝 Name validation
- 🛡️ SQL injection protection
- 🚫 XSS protection
- 📊 Audit logging
- 🐳 Docker support
- ⚡ Rate limiting
- 💾 Database backup
- ✅ Comprehensive testing

## Requirements

- Python 3.9+
- Docker and Docker Compose (optional)
- SQLite3

## Installation

### Local Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/PhoneBook_API.git
cd PhoneBook_API
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python init_db.py
```

5. Run the application:
```bash
uvicorn main:app --reload
```

### Docker Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/PhoneBook_API.git
cd PhoneBook_API
```

2. Build and run with Docker Compose:
```bash
docker-compose up --build
```

## API Documentation

Once the application is running, you can access the API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Testing

### Unit Tests
```bash
python -m pytest test_phonebook.py -v
```

### API Tests
```bash
./test_api.ps1
```

### Docker Tests
```bash
./test_docker.ps1
```

## Configuration

The application can be configured using environment variables:

- `DATABASE_FILE`: Path to the SQLite database file
- `SECRET_KEY`: Secret key for JWT token generation
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `RATE_LIMIT`: Number of requests per minute
- `BACKUP_INTERVAL`: Database backup interval in minutes

## Security Features

- JWT-based authentication
- Role-based access control
- Input validation
- SQL injection protection
- XSS protection
- Rate limiting
- Audit logging
- Database backup

## License

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request 