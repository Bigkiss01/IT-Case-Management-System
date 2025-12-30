FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for mysqlclient sometimes)
RUN apt-get update && apt-get install -y default-libmysqlclient-dev build-essential && rm -rf /var/lib/apt/lists/*

# Copy requirements from backend folder
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code from backend/src
COPY backend/src/ .

# Expose port
EXPOSE 5000

CMD ["python", "app.py"]
