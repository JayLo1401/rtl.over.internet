"""Start: python -m app"""

import logging
import sys

import uvicorn

from .config import ConfigError, load_settings
from .main import create_app


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = load_settings()
    except ConfigError as exc:
        logging.getLogger("roi").error("Konfiguration: %s", exc)
        return 2
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.http_host,
        port=settings.http_port,
        proxy_headers=False,  # X-Forwarded-* wertet die App selbst aus (ROI_TRUSTED_PROXIES)
        server_header=False,
        date_header=False,
        ws_max_size=64 * 1024,
        ws_ping_interval=20,
        ws_ping_timeout=20,
        access_log=False,
        log_config=None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
