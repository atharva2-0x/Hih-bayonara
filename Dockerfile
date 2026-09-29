# One image for every zone; each container runs exactly one role.
# Hardening (read-only rootfs, no capabilities, seccomp, gVisor, cpusets,
# per-zone networks) is applied at runtime by docker-compose.yml.
ARG BASE_IMAGE=python:3.11-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Dependencies come from a local wheelhouse (make wheels): reproducible builds
# with no network access needed inside the build container.
COPY wheelhouse/ /wheels/
COPY requirements.txt /app/requirements.txt
RUN pip install --no-index --find-links /wheels -r /app/requirements.txt && rm -rf /wheels

COPY doubleblind/ /app/doubleblind/
WORKDIR /app

# Unprivileged runtime user. Data directories exist in the image so that fresh
# named volumes are initialised with the right owner.
RUN groupadd --gid 10001 db && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin db \
 && mkdir -p /var/lib/doubleblind /drill-out /vault/red /state/red /state/blue /metrics \
 && chown -R 10001:10001 /var/lib/doubleblind /drill-out /vault/red /state/red /state/blue \
 && python -m compileall -q /app/doubleblind

USER 10001:10001
ENTRYPOINT ["python", "-m", "doubleblind"]
CMD ["--help"]
