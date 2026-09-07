"""Storage backend: S3 when buckets are configured, _localstore otherwise.

Local mode mirrors the S3 layout exactly so flipping to real buckets is
an env change, not a code change:
    assets    -> {STORAGE_DIR}/assets/{userId}/{recordId}/{assetId}.{ext}
    manifests -> {STORAGE_DIR}/manifests/v1/{recordId}.json
"""

import json
import os
import shutil
from pathlib import Path

ASSETS_BUCKET = os.environ.get("S3_ASSETS_BUCKET") or None
MANIFESTS_BUCKET = os.environ.get("S3_MANIFESTS_BUCKET") or None
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")
# Public base for manifest URLs. Defaults to the raw S3 endpoint; set to
# https://manifests.sessionseal.com (Cloudflare-fronted bucket) to serve
# manifests from the branded domain. No trailing slash.
MANIFESTS_PUBLIC_BASE = (os.environ.get("MANIFESTS_PUBLIC_BASE") or "").rstrip("/") or None
STORAGE_DIR = Path(os.environ.get(
    "STORAGE_DIR",
    Path(__file__).resolve().parent.parent.parent / "_localstore"))
HEIMDALL_PUBLIC_URL = os.environ.get("HEIMDALL_PUBLIC_URL",
                                     "http://127.0.0.1:8000")

LOCAL_BUCKET = "_localstore"  # recorded in assets.s3_bucket in local mode

_s3 = None
if ASSETS_BUCKET or MANIFESTS_BUCKET:
    import boto3
    _s3 = boto3.client("s3", region_name=AWS_REGION)


def assets_bucket() -> str:
    return ASSETS_BUCKET or LOCAL_BUCKET


def fetch_asset(key: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if ASSETS_BUCKET:
        _s3.download_file(ASSETS_BUCKET, key, str(dest))
    else:
        shutil.copy2(STORAGE_DIR / "assets" / key, dest)
    return dest


def put_asset(src: Path, key: str, content_type: str = "audio/wav") -> None:
    if ASSETS_BUCKET:
        _s3.upload_file(str(src), ASSETS_BUCKET, key,
                        ExtraArgs={"ContentType": content_type})
    else:
        dest = STORAGE_DIR / "assets" / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def put_manifest(doc: dict, record_id: str) -> tuple[str, str]:
    """Publish the public manifest. Returns (key, public_url)."""
    key = f"v1/{record_id}.json"
    body = json.dumps(doc, indent=2, default=str).encode()
    if MANIFESTS_BUCKET:
        _s3.put_object(Bucket=MANIFESTS_BUCKET, Key=key, Body=body,
                       ContentType="application/json")
        base = MANIFESTS_PUBLIC_BASE or \
            f"https://{MANIFESTS_BUCKET}.s3.{AWS_REGION}.amazonaws.com"
        url = f"{base}/{key}"
    else:
        dest = STORAGE_DIR / "manifests" / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
        url = f"{HEIMDALL_PUBLIC_URL}/manifests/{key}"
    return key, url
