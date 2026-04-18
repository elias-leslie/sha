from __future__ import annotations

import sys
from pathlib import Path

from app.source_packs.catalog import build_source_catalog


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> int:
    try:
        catalog = build_source_catalog(_repo_root())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        f"Wrote control-packs/catalog.json ({catalog.pack_count} packs, {catalog.control_count} controls)",
        file=sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
