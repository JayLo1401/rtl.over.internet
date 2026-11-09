# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
ARG VERSION=dev
ENV ROI_VERSION=$VERSION \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ROI_DATA_DIR=/data \
    ROI_HTTP_HOST=127.0.0.1 \
    ROI_HTTP_PORT=8090
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin roi \
 && mkdir /data && chown roi:roi /data && chmod 700 /data
COPY --from=build /install /usr/local
COPY app /srv/app
WORKDIR /srv
USER roi
VOLUME ["/data"]
EXPOSE 8090/tcp 3478/udp 3479/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["python", "-c", "import os,urllib.request; h=os.environ.get('ROI_HTTP_HOST','127.0.0.1'); h='127.0.0.1' if h in ('0.0.0.0','::') else h; urllib.request.urlopen(f'http://{h}:'+os.environ.get('ROI_HTTP_PORT','8090')+'/healthz', timeout=3)"]
CMD ["python", "-m", "app"]
