from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.source_packs.catalog import build_source_catalog, load_source_catalog, load_source_pack
from app.source_packs.contracts import SourceCatalog, SourcePack

router = APIRouter(prefix="/api/source-packs", tags=["source-packs"])


@router.get("", response_model=SourceCatalog)
def list_source_packs() -> SourceCatalog:
    try:
        return load_source_catalog()
    except FileNotFoundError:
        try:
            return build_source_catalog()
        except ValueError as exc:
            raise HTTPException(status_code=503, detail="source pack catalog unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="source pack catalog unavailable") from exc


@router.get("/{pack_id:path}", response_model=SourcePack)
def get_source_pack(pack_id: str) -> SourcePack:
    try:
        return load_source_pack(pack_id)
    except FileNotFoundError:
        try:
            build_source_catalog()
            return load_source_pack(pack_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="source pack not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=503, detail="source pack unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="source pack unavailable") from exc
