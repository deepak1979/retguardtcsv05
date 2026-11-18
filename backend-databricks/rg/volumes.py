"""Unity Catalog Volume access via the Databricks SDK's Files API.

Confirmed by direct testing: a Databricks App's container does NOT mount UC Volumes as plain POSIX
filesystem paths the way a notebook/cluster/job does (`Path("/Volumes/...").is_dir()` returns False
even for a real, accessible volume) - every original v03/plan assumption that `pathlib.Path` would
just work against a `/Volumes/...` path was wrong for this compute type. The SDK's Files API
(`w.files.*`) is the actual mechanism; this module wraps it behind the same small handful of
operations rg/docscan.py, rg/redact.py and rg/archive.py already need, so those modules stay close to
their original file-handling shape instead of being rewritten around REST calls directly.
"""
from __future__ import annotations

import io
from functools import lru_cache

from databricks.sdk import WorkspaceClient
from databricks.sdk.errors import NotFound


@lru_cache(maxsize=1)
def _client() -> WorkspaceClient:
    return WorkspaceClient()


def is_dir(path: str) -> bool:
    try:
        _client().files.get_directory_metadata(path)
        return True
    except NotFound:
        return False


def list_files(path: str, suffix: str | None = None) -> list[dict]:
    """Every file (not directory) under `path`, recursively - list_directory_contents() itself is
    one level deep only, so this walks subdirectories itself. Each entry: path, name, size, modified_at
    (a datetime) - mirroring the Path.stat()-derived values the local-folder code used to build.
    Confirmed by direct testing: list_directory_contents()'s own `last_modified` is epoch
    milliseconds (an int) - a different shape from get_metadata()'s RFC-2822 string."""
    import datetime as dt

    out: list[dict] = []
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            entries = list(_client().files.list_directory_contents(d))
        except NotFound:
            continue
        for e in entries:
            if e.is_directory:
                stack.append(e.path)
                continue
            if suffix and not e.name.lower().endswith(suffix.lower()):
                continue
            modified_at = (dt.datetime.fromtimestamp(e.last_modified / 1000, tz=dt.timezone.utc)
                          if e.last_modified else None)
            out.append({"path": e.path, "name": e.name, "size": e.file_size, "modified_at": modified_at})
    return sorted(out, key=lambda r: r["path"])


def read_bytes(path: str) -> bytes:
    return _client().files.download(path).contents.read()


def write_bytes(path: str, data: bytes) -> None:
    _client().files.upload(path, io.BytesIO(data), overwrite=True)


def delete(path: str) -> None:
    try:
        _client().files.delete(path)
    except NotFound:
        pass


def delete_tree(path: str) -> None:
    """Remove every file under `path` (there is no directory-level delete in the Files API). A quiet
    no-op when `path` doesn't exist - same tolerance as delete()."""
    for f in list_files(path):
        delete(f["path"])
