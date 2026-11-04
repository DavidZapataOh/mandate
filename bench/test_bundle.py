import pytest

from bench.bundle import bundle_sizes

# gzip -9 -n sizes, from the gzip CLI: 1000 x "a" -> 29, empty -> 20,
# 300 x "console" -> 44.
PAGE = (
    '<script type="module" src="/console/assets/a.js"></script>'
    '<link rel="stylesheet" href="/console/assets/s.css">'
)


def test_a_page_counts_what_it_names_and_the_rest_is_lazy(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a.js").write_bytes(b"a" * 1000)
    (tmp_path / "assets" / "s.css").write_bytes(b"")
    (tmp_path / "assets" / "late.wasm").write_bytes(b"console" * 300)
    (tmp_path / "assets" / "font.woff2").write_bytes(b"x" * 5000)
    (tmp_path / "index.html").write_text(PAGE)
    (tmp_path / "holder.html").write_text(PAGE.split("<link")[0])
    assert bundle_sizes(tmp_path) == {
        "console.holder": 29,
        "console.index": 49,
        "console.lazy": 44,
    }


def test_a_missing_build_or_asset_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="no console build"):
        bundle_sizes(tmp_path)
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text(PAGE)
    with pytest.raises(FileNotFoundError):
        bundle_sizes(tmp_path)
