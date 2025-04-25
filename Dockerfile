FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_FILE=/app/data/phonebook.db
ENV SECRET_KEY=your-secret-key-here
ENV LOG_LEVEL=INFO
ENV AUDIT_LOG_FILE=/app/logs/audit.log

# Create necessary directories and set permissions
RUN mkdir -p /app/data /app/logs /app/data/backups && \
    touch /app/data/phonebook.db && \
    chmod 666 /app/data/phonebook.db && \
    chmod 777 /app/logs && \
    chmod 777 /app/data/backups

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"] 