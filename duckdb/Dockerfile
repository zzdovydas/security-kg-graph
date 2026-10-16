# Sidecar container that ships the DuckDB CLI so the persistent kg.duckdb file
# can be inspected / queried interactively from outside the Node ingest process.
# All actual database population (CREATE TABLE / CREATE INDEX from parquet) is
# performed by the Node ingest service in ../ingest/index.js — this container
# does NOT build the database itself.
#
# Typical use:
#   docker compose exec duckdb duckdb /data/kg.duckdb
#
# Debian-based because the official DuckDB CLI is glibc-linked.
FROM debian:bookworm-slim

ARG DUCKDB_VERSION=1.1.3

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/duckdb.zip \
      "https://github.com/duckdb/duckdb/releases/download/v${DUCKDB_VERSION}/duckdb_cli-linux-amd64.zip" \
 && unzip /tmp/duckdb.zip -d /usr/local/bin \
 && rm /tmp/duckdb.zip \
 && chmod +x /usr/local/bin/duckdb \
 && duckdb --version

WORKDIR /data

# Keep the container alive so `docker exec` can be used to run ad-hoc queries.
CMD ["sleep", "infinity"]
