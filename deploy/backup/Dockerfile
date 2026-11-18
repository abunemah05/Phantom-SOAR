# syntax=docker/dockerfile:1
# Backup job image: the same Postgres version as the database (pg_dump must not be older than the server)
# plus deploy/backup/backup.sh. Runs as the unprivileged "postgres" user.
ARG PG_IMAGE=postgres:16.10-alpine
FROM ${PG_IMAGE}

USER root
COPY backup.sh /usr/local/bin/phantom-backup
RUN chmod 0755 /usr/local/bin/phantom-backup \
    && mkdir -p /backups \
    && chown postgres:postgres /backups
USER postgres

ENTRYPOINT ["/usr/local/bin/phantom-backup"]
CMD ["loop"]
