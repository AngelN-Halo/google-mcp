FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY auth.py config.py errors.py google_directory.py models.py request_context.py server.py ./

RUN chmod 0444 /app/*.py /app/requirements.txt \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001:10001

EXPOSE 8000

CMD ["python", "server.py"]

FROM base AS test
USER root
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt \
    && chmod 0444 /app/requirements-dev.txt
USER 10001:10001

FROM base AS runtime
