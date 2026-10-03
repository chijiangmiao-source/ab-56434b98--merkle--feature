FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Image-build sanity: the app package must import cleanly in the built image.
RUN python -c "import app.main"

# --- verify image: runtime image + test/smoke tooling ----------------------
FROM base AS verify

COPY requirements-test.txt pytest.ini ./
COPY tests ./tests
COPY scripts ./scripts
RUN pip install --no-cache-dir -r requirements-test.txt

# --- runtime image ----------------------------------------------------------
FROM base AS runtime

EXPOSE 8000
ENV BUOY_DB=/data/buoy.db
VOLUME ["/data"]

HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=3s \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2); sys.exit(0 if json.load(r)['status']=='ok' else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
