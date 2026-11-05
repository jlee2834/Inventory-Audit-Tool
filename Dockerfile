FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --system --uid 10001 --create-home audit && mkdir -p /data && chown audit:audit /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py backup.py ./
COPY templates ./templates
COPY static ./static
USER audit
EXPOSE 8000
CMD ["gunicorn","--bind","0.0.0.0:8000","--workers","2","--threads","4","--access-logfile","-","app:app"]
