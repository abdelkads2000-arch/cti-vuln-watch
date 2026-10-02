FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first for layer caching.
COPY pyproject.toml ./
RUN mkdir -p src/cti && touch src/cti/__init__.py \
 && pip install ".[test]" \
 && rm -rf src

COPY src ./src
COPY config ./config
COPY tests ./tests
COPY docker/entrypoint.sh /entrypoint.sh
RUN pip install --no-deps . \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin cti \
 && chmod 0755 /entrypoint.sh

USER 10001:10001
ENV CTI_CONFIG_DIR=/app/config

ENTRYPOINT ["/entrypoint.sh"]
CMD ["worker"]
