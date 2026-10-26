FROM python:3.12-slim

WORKDIR /app

# System deps needed by psycopg2 and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional multiparty-HE extra (unverified on this base image) - build with --build-arg INSTALL_MHE=true
ARG INSTALL_MHE=false
COPY backend/requirements-mhe.txt .
RUN if [ "$INSTALL_MHE" = "true" ]; then pip install --no-cache-dir -r requirements-mhe.txt; fi

COPY backend/ .

RUN mkdir -p storage/uploads storage/reports storage/node_a storage/node_b storage/node_c
# Windows checkouts often convert LF -> CRLF, which makes the container fail with
# "exec ./entrypoint.sh: no such file or directory". Normalise it here.
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "run:app"]
