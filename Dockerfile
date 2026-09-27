FROM mcr.microsoft.com/playwright/python:v1.63.0-noble@sha256:96b39581c89131729a7ecb8d532314af54c7f9bcc7a61fe15c7a9e77602acf59
ENV PYTHONUTF8=1 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PRIVACY_BOT_DATA=/data
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY pyproject.toml ./
COPY privacy_bot ./privacy_bot
RUN pip install --no-cache-dir --no-deps . && mkdir -p /data && chown 1000:1000 /data
USER 1000:1000
EXPOSE 8791
CMD ["python", "-X", "utf8", "-m", "uvicorn", "privacy_bot.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8791", "--no-access-log", "--no-proxy-headers"]
