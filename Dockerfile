FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
COPY version.txt /app/version.txt
RUN chmod +x /app/entrypoint.sh

VOLUME ["/data"]

ENV INTERVAL_SECONDS=10

ENTRYPOINT ["/app/entrypoint.sh"]
