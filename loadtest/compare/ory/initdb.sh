#!/usr/bin/env bash
# The databases of the Ory comparison run (#913), on the shared PostgreSQL:
# one database and one owner role each for Hydra and Kratos. PostgreSQL's
# image runs this once, when it initialises an empty data directory
# (/docker-entrypoint-initdb.d). The passwords come from the container's
# environment (compose.yaml) and reach psql on stdin, not on a command line;
# ory.sh makes them from letters and digits only, so they need no quoting.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" << SQL
CREATE ROLE hydra LOGIN PASSWORD '${HYDRA_DB_PASSWORD:?}';
CREATE DATABASE hydra OWNER hydra;
CREATE ROLE kratos LOGIN PASSWORD '${KRATOS_DB_PASSWORD:?}';
CREATE DATABASE kratos OWNER kratos;
SQL
