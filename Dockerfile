FROM python:3.13-slim

WORKDIR /app
COPY dist ./dist

EXPOSE 10000

# Migration fallback only: serves immutable files and opens no P2P connections.
CMD ["python", "-m", "http.server", "10000", "--bind", "0.0.0.0", "--directory", "dist"]
