# Sextant: web UI + CLI
FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Sextant" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary" \
      org.opencontainers.image.vendor="Andreas Lindstedt" \
      org.opencontainers.image.description="Proprietary. All rights reserved. See LICENSE."

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SEXTANT_DATA_DIR=/data SEXTANT_THEMES_DIR=/data/themes

# WeasyPrint needs Pango; fontconfig so the bundled Open Sans is found.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libcairo2 fontconfig \
      fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
 && mkdir -p /usr/local/share/fonts/opensans \
 && cp src/sextant/themes/_fonts/*/*.ttf /usr/local/share/fonts/opensans/ && fc-cache -f

RUN useradd --system --uid 10001 --home /data sextant && mkdir -p /data && chown sextant /data
USER sextant
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
ENTRYPOINT ["sextant"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
