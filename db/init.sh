#!/bin/bash

echo "Running init.sh to process init.sql..."

# Replace placeholder in init.sql and pipe into psql
sed "s|\${ADMIN_PASSWORD_HASH}|${POSTGRES_PASSWORD}|g" /docker-entrypoint-initdb.d/init.sql | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
