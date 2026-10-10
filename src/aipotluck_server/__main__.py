"""Support ``python -m aipotluck_server`` as an alias for ``potluck-server``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
