FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install . && \
    useradd --system --uid 10001 --create-home gateway && \
    mkdir -p /data && chown gateway:gateway /data

USER gateway
VOLUME ["/data"]
ENTRYPOINT ["icloud-webdav"]
CMD ["serve", "--config", "/data/icloud-webdav.toml", "--non-interactive"]
