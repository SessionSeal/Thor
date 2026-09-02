"""C2PA manifest build + sign via c2patool.

The manifest is the structured, signed record. Signing it with the
platform key makes it tamper-evident (any change breaks the signature)
and attributable to the platform. The certificate is self-attested (our
own dev CA, on no trust list), so verifiers will report
"signingCredential.untrusted" -- expected for this MVP, and stated
explicitly inside the record itself.

c2patool notes (verified against c2patool 0.27.x):
  - the manifest definition JSON carries `alg`, `private_key`, `sign_cert`
    paths (dev-only mechanism, fine for this MVP);
  - c2patool computes the hard-binding `c2pa.hash.data` assertion itself
    when embedding, so the exact-byte binding of the signed asset is
    handled by the tool;
  - `c2pa.created` actions require a `digitalSourceType`;
  - a manifest is stored embedded in the output asset; we keep the signed
    asset plus the manifest report in private storage.
"""

import json
import subprocess
from pathlib import Path

import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGNING_DIR = Path(os.environ.get("SIGNING_DIR", PROJECT_ROOT / "signing"))
PRIVATE_KEY = SIGNING_DIR / "es256_private.key"
CERT_CHAIN = SIGNING_DIR / "es256_certs.pem"

CLAIM_GENERATOR = "music-provenance-mvp/0.1.0"
SIGNATURE_ALG = "es256"

ASSERTION_NAMESPACE = "org.musicprovenance.mvp"


def cert_subject() -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", str(CERT_CHAIN), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip().removeprefix("subject=")


def build_manifest_definition(
    *,
    created_at_utc: str,
    master_sha256: str,
    master_fingerprint_compressed: str,
    fingerprint_duration: float,
    stem_hashes: list[dict],
    project_hashes: dict,
    coherence: dict,
) -> dict:
    """Assemble the manifest definition JSON for c2patool.

    The record's claims are custody, integrity, coherence, and priority.
    It does not claim authorship, and no assertion below implies it.
    """
    return {
        "alg": SIGNATURE_ALG,
        "private_key": str(PRIVATE_KEY),
        "sign_cert": str(CERT_CHAIN),
        "claim_generator": CLAIM_GENERATOR,
        "title": "Music provenance record (custody/integrity/coherence/priority)",
        "assertions": [
            {
                # Actions: when this material was sealed and by what software.
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "when": created_at_utc,
                            "digitalSourceType": (
                                "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                            ),
                            "softwareAgent": {
                                "name": "music-provenance-mvp",
                                "version": "0.1.0",
                            },
                        }
                    ]
                },
            },
            {
                # Soft binding: ties the record to the *sound* of the track,
                # so it still matches after platforms re-encode the audio.
                "label": "c2pa.soft-binding",
                "data": {
                    "alg": "chromaprint",
                    "blocks": [
                        {
                            "scope": {},
                            "value": master_fingerprint_compressed,
                        }
                    ],
                },
            },
            {
                # Platform-namespace evidence assertion. The exact byte hash of
                # the *original uploaded* master lives here (the signed asset's
                # own hard binding, c2pa.hash.data, is added by c2patool).
                "label": f"{ASSERTION_NAMESPACE}.evidence",
                "data": {
                    "master": {
                        "sha256": master_sha256,
                        "note": "hash of the original uploaded master, before manifest embedding",
                    },
                    "stems": stem_hashes,
                    "project": project_hashes,
                    "coherence": coherence,
                    "fingerprint": {
                        "algorithm": "chromaprint",
                        "duration_seconds": fingerprint_duration,
                    },
                    "signer_disclosure": {
                        "self_attested": True,
                        "note": (
                            "This record is signed with a self-attested development "
                            "certificate that is not on any trust list. The platform "
                            "vouches for itself; no recognized authority vouches for "
                            "the platform."
                        ),
                    },
                    "claims": {
                        "proves": [
                            "custody: this exact material existed here at the sealed time",
                            "integrity: files matching the sealed hashes are unaltered",
                            "coherence: whether the stems verifiably reconstruct the master",
                            "priority: a signed timestamp",
                        ],
                        "does_not_prove": "authorship of the music",
                    },
                },
            },
        ],
    }


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
