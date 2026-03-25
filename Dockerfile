FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends dnsutils && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir . 

COPY alembic.ini .
COPY alembic/ alembic/
COPY hyrule_cloud/ hyrule_cloud/

EXPOSE 8402

CMD ["uvicorn", "hyrule_cloud.app:app", "--host", "::", "--port", "8402"]
