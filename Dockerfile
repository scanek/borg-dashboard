FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV BORG_CACHE_DIR=/tmp/borg_cache

# Note on container permissions:
# BorgBackup requires exclusive write locks (/repos/.../lock.roster). On most NAS systems
# (Synology, TrueNAS, OMV), repositories on disk belong to root. Running as root guarantees
# lock management works seamlessly, while host file integrity is enforced via read-only (:ro) binds.

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        borgbackup \
        python3 \
        python3-fastapi \
        python3-uvicorn \
        python3-jinja2 \
        python3-pydantic \
        ca-certificates \
        tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/ /app/

EXPOSE 8099
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8099"]
