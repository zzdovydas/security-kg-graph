# Plain PostgreSQL. Parquet data is loaded by the ingest service, which reads
# the files with DuckDB and writes them here through DuckDB's postgres extension
# (see importParquetToPostgres in ../ingest/index.js).
ARG PG_MAJOR=17

FROM postgres:${PG_MAJOR}-bookworm

# Bulk-load friendly settings; the database is a rebuildable copy of the parquet files.
CMD ["postgres", \
     "-c", "max_wal_size=4GB", \
     "-c", "checkpoint_timeout=15min", \
     "-c", "maintenance_work_mem=512MB"]
