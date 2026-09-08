"""C2PA manifest signing via c2patool.

The manifest is the structured, signed record. Signing it with the
SessionSeal key makes it tamper-evident (any change breaks the signature)
and attributable to SessionSeal.

Certificate: today the signing cert is a self-attested chain (our own CA,
on no trust list), so verifiers report "signingCredential.untrusted". The
record discloses this in its `signer_disclosure` assertion. Swapping in a
CA-issued, C2PA-trust-listed cert is a file swap in the signing dir — no
code change (see infra C2PA cert runbook).

c2patool notes (verified against c2patool 0.27.x):
  - the definition JSON carries `alg`, `private_key`, `sign_cert` paths for
    c2patool's use; these are stripped from the PUBLISHED manifest;
  - c2patool computes the hard-binding `c2pa.hash.data` assertion itself
    when embedding, so the exact-byte binding of the signed asset is
    handled by the tool;
  - `c2pa.created` actions require a `digitalSourceType`;
  - a manifest is stored embedded in the output asset.
"""

import json
import subprocess
from pathlib import Path

import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGNING_DIR = Path(os.environ.get("SIGNING_DIR", PROJECT_ROOT / "signing"))
PRIVATE_KEY = SIGNING_DIR / "es256_private.key"
CERT_CHAIN = SIGNING_DIR / "es256_certs.pem"

APP_NAME = "SessionSeal"
APP_VERSION = "1.0.0"
CLAIM_GENERATOR = f"{APP_NAME}/{APP_VERSION}"
SIGNATURE_ALG = "es256"

# Reverse-DNS namespace for SessionSeal's custom assertion.
ASSERTION_NAMESPACE = "com.sessionseal"


def cert_subject() -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", str(CERT_CHAIN), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip().removeprefix("subject=")


def published_view(definition: dict) -> dict:
    """The manifest definition minus c2patool signing config (private_key,
    sign_cert) — safe to publish publicly. Never publish the raw definition."""
    return {k: v for k, v in definition.items()
            if k not in ("private_key", "sign_cert")}


def sign(master_wav: Path, manifest_definition: dict, out_dir: Path) -> tuple[Path, Path, dict]:
    """Sign the master with the manifest embedded.

    Returns (signed_asset_path, manifest_definition_path, c2patool_report).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    definition_path = out_dir / "manifest_definition.json"
    definition_path.write_text(json.dumps(manifest_definition, indent=2))

    signed_path = out_dir / f"signed_{master_wav.name}"
    result = subprocess.run(
        [
            "c2patool", str(master_wav),
            "-m", str(definition_path),
            "-o", str(signed_path),
            "-f",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"c2patool signing failed: {result.stderr.strip()}")

    report = json.loads(result.stdout)
    (out_dir / "manifest_report.json").write_text(json.dumps(report, indent=2))
    return signed_path, definition_path, report
