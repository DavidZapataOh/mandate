"""Console build sizes: gzip -9 bytes of each page's first load and the rest."""

import gzip
import re
from pathlib import Path

_NAMED = re.compile(r'(?:src|href)="/console/(assets/[^"?#]+\.(?:js|css))"')
_LATER = frozenset({".js", ".css", ".wasm"})


def gzip_size(data: bytes) -> int:
    """Bytes of ``data`` after gzip -9 with no timestamp."""
    return len(gzip.compress(data, compresslevel=9, mtime=0))


def bundle_sizes(dist: Path) -> dict[str, int]:
    """Gzip -9 bytes per page (``console.<stem>``) and of ``console.lazy``.

    A page counts the scripts and styles its HTML names; ``console.lazy``
    counts every script, style and wasm asset no page names.

    Raises:
        FileNotFoundError: No page in ``dist``, or a named asset is missing.
    """
    pages = sorted(dist.glob("*.html"))
    if not pages:
        raise FileNotFoundError(f"no console build in {dist}")
    sizes: dict[str, int] = {}
    named: set[str] = set()
    for page in pages:
        assets = sorted(set(_NAMED.findall(page.read_text())))
        named.update(assets)
        sizes[f"console.{page.stem}"] = sum(
            gzip_size((dist / asset).read_bytes()) for asset in assets
        )
    later = [
        path
        for path in sorted((dist / "assets").glob("*"))
        if path.suffix in _LATER and f"assets/{path.name}" not in named
    ]
    sizes["console.lazy"] = sum(gzip_size(path.read_bytes()) for path in later)
    return dict(sorted(sizes.items()))
