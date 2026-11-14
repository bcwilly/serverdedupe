FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 APP_DATA=/app/data
# ffmpeg/ffprobe: video + audio details, video frame matching, audio fingerprints, video thumbnails
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg tzdata p7zip-full \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
COPY static ./static

EXPOSE 5070
# One worker on purpose: the running scan lives in this process. Threads handle concurrent requests.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "1800", "--bind", "0.0.0.0:5070", "app:app"]
