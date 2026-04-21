from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.schemas.schema_exports import REPO_ROOT, write_exported_schema_documents


def main() -> None:
    for path in write_exported_schema_documents():
        print(path.relative_to(REPO_ROOT))


if __name__ == "__main__":
    main()
