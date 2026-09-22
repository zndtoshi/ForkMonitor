FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OBSERVER_HOST=0.0.0.0 \
    OBSERVER_ARCHIVE_MODE=1 \
    OBSERVER_STATE_DIR=/var/data/knots-fork-observer

WORKDIR /app
COPY observer.py ./observer.py
COPY dist ./dist

EXPOSE 10000

CMD ["python", "observer.py"]
