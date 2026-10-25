FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# openssl so the Terminal tab (and docker exec) can inspect/convert certificates
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static static
EXPOSE 8080
VOLUME ["/config", "/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/')"
CMD ["python", "app.py"]
