FROM python:3.11-slim

# Security hardening: Create unprivileged user
RUN groupadd -g 1001 aegisgroup && \
    useradd -u 1001 -g aegisgroup -s /bin/bash -m aegisuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Adjust permissions
RUN chown -R aegisuser:aegisgroup /app

USER aegisuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
