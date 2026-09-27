FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LAB_DATA_DIR=/app/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY scripts ./scripts

# 构建内置样例证书（离线生成，不访问网络）
RUN python scripts/generate_samples.py /app/data_bundled/samples

VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
