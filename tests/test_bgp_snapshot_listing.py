from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from hyrule_cloud.api.bgp import _snapshot_download_available
from hyrule_cloud.db import BGPSnapshotRow


def _row(path: Path | None, *, expires_at: datetime | None) -> BGPSnapshotRow:
    return cast(
        BGPSnapshotRow,
        SimpleNamespace(
            artifact_path=str(path) if path is not None else None,
            expires_at=expires_at,
        ),
    )


def test_snapshot_listing_only_accepts_live_files(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "snapshot.jsonl.gz"
    artifact.write_bytes(b"snapshot")

    assert _snapshot_download_available(_row(artifact, expires_at=now + timedelta(hours=1)), now)
    assert not _snapshot_download_available(_row(None, expires_at=None), now)
    assert not _snapshot_download_available(_row(tmp_path / "missing.gz", expires_at=None), now)
    assert not _snapshot_download_available(
        _row(artifact, expires_at=now - timedelta(seconds=1)), now
    )
