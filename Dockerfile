FROM python:3.11-slim

# Install curl untuk healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy kode sumber
COPY src/ ./src/

EXPOSE 8000

# Jalankan dengan Uvicorn
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]