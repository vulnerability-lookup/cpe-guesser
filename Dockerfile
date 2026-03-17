# syntax=docker/dockerfile:1

FROM alpine:latest

COPY . /app

RUN <<EOF
apk update
apk add py3-pip
pip install pipx --break-system-packages
pipx install --global uv
EOF

# Disable development dependencies
ENV UV_NO_DEV=1

WORKDIR /app

RUN uv sync --locked

# configuration
COPY <<EOF /app/config/settings.yaml
server:
  port: 8000
valkey:
  host: valkey
  port: 6379
  db: 8
cpe:
  path: '/data/nvdcpe-2.0.tar'
  source: 'https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz'
EOF

# entrypoint script
COPY <<EOF entrypoint.sh
#!/bin/ash
set -e

uv run cpe-import
uv run cpe-server
EOF

RUN chmod u+x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
