FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for mysqlclient sometimes)
RUN apt-get update && apt-get install -y default-libmysqlclient-dev build-essential

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

CMD ["python", "app.py"]
