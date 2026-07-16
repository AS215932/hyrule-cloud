FROM python:3.12-slim AS builder

WORKDIR /src

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY hyrule_cloud/ hyrule_cloud/
RUN pip install --prefix=/install --no-cache-dir .

FROM python:3.12-slim AS runtime

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends dnsutils && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /usr/local/

COPY alembic.ini .
COPY alembic/ alembic/

FROM runtime AS worker

CMD ["hyrule-cloud-worker"]

FROM runtime AS api

EXPOSE 8402

CMD ["uvicorn", "hyrule_cloud.app:app", "--host", "::", "--port", "8402"]
