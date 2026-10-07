FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/iot-operator

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/entrypoint.sh /entrypoint.sh

RUN sed -i 's/\r$//' /entrypoint.sh /etc/nginx/nginx.conf \
    && chmod +x /entrypoint.sh \
    && mkdir -p /data

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1

EXPOSE 80 8090
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"

CMD ["/entrypoint.sh"]
