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

- Python 3.9+ (for local development)
- Docker and Docker Compose (for containerized deployment)
- SQLite3 (included in containers)

## Installation & Running

### Option 1: Docker Installation (Recommended)

1. **Prerequisites**:
   - Install [Docker](https://docs.docker.com/get-docker/)
   - Install [Docker Compose](https://docs.docker.com/compose/install/)

2. **Clone the repository**:
   ```bash
   git clone https://github.com/VineetKurapati/Input_Validation.git
   cd Input_Validation
   ```

3. **Build and run with Docker Compose**:
   ```bash
   docker-compose up --build
   ```
   This will:
   - Build the Docker image
   - Create necessary volumes for data persistence
   - Start the API server on port 8000

4. **Run in detached mode** (optional):
   ```bash
   docker-compose up --build -d
   ```

5. **Stop the containers**:
   ```bash
   docker-compose down
   ```

6. **View logs**:
   ```bash
   docker-compose logs
   ```

7. **Access the API**:
   - API endpoint: http://localhost:8000
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Option 2: Local Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/VineetKurapati/Input_Validation.git
   cd Input_Validation
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

## Docker Commands Reference

### Basic Commands
```bash
# Build and start containers
docker-compose up --build

# Start containers in detached mode
docker-compose up -d

# Stop containers
docker-compose down

# View logs
docker-compose logs

# View logs in real-time
docker-compose logs -f

# Check container status
docker-compose ps
```

### Data Management
- Data is persisted in Docker volumes:
  - Database: `./data:/app/data`
  - Logs: `./logs:/app/logs`

### Environment Variables
The Docker container can be configured using environment variables in `docker-compose.yml`:
```yaml
environment:
  - DATABASE_FILE=/app/data/phonebook.db
  - SECRET_KEY=your-secret-key-here
  - LOG_LEVEL=INFO
  - AUDIT_LOG_FILE=/app/logs/audit.log
```

### Docker Health Checks
The container includes health checks that monitor:
- API availability
- Database connectivity
- Log write permissions

## Testing

### Running Tests in Docker
1. Build and run the test container:
   ```bash
   docker-compose -f docker-compose.test.yml up --build
   ```

### Running Tests Locally
```bash
# Set up test environment
python test_setup.py

# Run tests with verbose output
python -m pytest test_phonebook.py -v
```

## API Documentation

Once the application is running, access the API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Default Users
The system comes with two pre-configured users:
- Read-only user:
  - Username: `reader`
  - Password: `readerpass`
- Read-write user:
  - Username: `writer`
  - Password: `writerpass`

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