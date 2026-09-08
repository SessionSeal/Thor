"""End-to-end seal pipeline.

register():
  1. verify stems <-> master coherence and logicx <-> stems/master
     same-origin confidence (app.same_origin);
  2. watermark the master with audiowmark (payload = the record id);
  3. fingerprint the *watermarked* master (the distributed form);
  4. build + sign a C2PA manifest over the watermarked master:
     hard binding (c2patool's own hash of the asset), soft binding
     (chromaprint), and a platform assertion hard-binding the .logicx zip
     and stems by signed SHA-256 (c2patool cannot embed manifests inside
     zip containers, so the project's hard binding lives as a signed hash
     commitment in the master's manifest);
  5. store everything: private evidence bundle + DB row.

link(): given any audio copy, try all three recovery mechanisms --
  audiowmark payload (exact record id), chromaprint similarity against
  every registered fingerprint, and an embedded C2PA manifest (survives
  lossless copies, is stripped by platform re-encoding -- demonstrating
  why the remote record exists).

Every output states self-attested signing and the custody/integrity/
coherence/priority scope. Nothing claims authorship.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import soundfile as sf

from . import audio, fingerprint, hashing, manifest, pg, same_origin, store

_SERVICE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = Path(os.environ.get(
    "STORAGE_DIR", _SERVICE_ROOT.parent / "_localstore"))
EVIDENCE = STORAGE_DIR / "evidence"
RELEASE = STORAGE_DIR / "release"
WATERMARK_KEY = Path(os.environ.get(
    "WATERMARK_KEY_PATH", _SERVICE_ROOT / "signing" / "watermark.key"))


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _aw_key() -> Path:
    """Secret watermarking key. Without one, audiowmark uses a public
    default key and anyone can decode a payload and re-embed it into
    unrelated audio (copy attack). Generated once, kept out of the repo."""
    if not WATERMARK_KEY.exists():
        r = _run(["audiowmark", "gen-key", str(WATERMARK_KEY)])
        if r.returncode != 0 or not WATERMARK_KEY.exists():
            raise RuntimeError(
                f"audiowmark gen-key failed: {r.stderr.strip()[:300]}")
    return WATERMARK_KEY


def aw_embed(src_wav: Path, out_wav: Path, hex_payload: str) -> None:
    r = _run(["audiowmark", "add", "--key", str(_aw_key()), "--strength", "10",
              str(src_wav), str(out_wav), hex_payload])
    if r.returncode != 0 or not out_wav.exists():
        raise RuntimeError(f"audiowmark embed failed: {r.stderr.strip()[:300]}")


def aw_extract(wav: Path) -> tuple[str | None, float]:
    r = _run(["audiowmark", "get", "--key", str(_aw_key()), str(wav)])
    best_hex, best_score = None, -1.0
    for line in r.stdout.splitlines():
        m = re.match(r"pattern\s+\S+\s+([0-9a-f]{32})\s+([\d.]+)", line.strip())
        if m and float(m.group(2)) > best_score:
            best_hex, best_score = m.group(1), float(m.group(2))
    return best_hex, best_score


def _build_manifest(record_id: str, created_at: str, *, master_sha: str,
                    signed_source_sha: str, logicx_sha: str,
                    stem_hashes: list[dict], fp_compressed: str,
                    fp_seconds: float, watermark_hex: str,
                    coherence: dict, sameorigin_summary: dict) -> dict:
    return {
        "alg": manifest.SIGNATURE_ALG,
        "private_key": str(manifest.PRIVATE_KEY),
        "sign_cert": str(manifest.CERT_CHAIN),
        "claim_generator": manifest.CLAIM_GENERATOR,
        "title": f"Provenance record {record_id} "
                 "(custody/integrity/coherence/priority)",
        "assertions": [
            {"label": "c2pa.actions.v2",
             "data": {"actions": [{
                 "action": "c2pa.created",
                 "when": created_at,
                 "digitalSourceType":
                     "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
                 "softwareAgent": {"name": manifest.APP_NAME,
                                   "version": manifest.APP_VERSION},
             }]}},
            {"label": "c2pa.soft-binding",
             "data": {"alg": "chromaprint",
                      "blocks": [{"scope": {}, "value": fp_compressed}]}},
            {"label": f"{manifest.ASSERTION_NAMESPACE}.record",
             "data": {
                 "record_id": record_id,
                 "master": {
                     "original_sha256": master_sha,
                     "watermarked_sha256": signed_source_sha,
                     "note": "hard binding of the signed asset itself is the "
                             "c2pa.hash.data assertion added by c2patool",
                 },
                 "project": {
                     "logicx_zip_sha256": logicx_sha,
                     "note": "hard binding by signed hash commitment; C2PA "
                             "manifests cannot be embedded in zip containers",
                 },
                 "stems": stem_hashes,
                 "watermark": {"algorithm": "audiowmark v0.6.5 (spread "
                                            "spectrum, keyed)",
                               "payload_hex": watermark_hex,
                               "strength": 10},
                 "fingerprint": {"algorithm": "chromaprint",
                                 "duration_seconds": fp_seconds},
                 "coherence": coherence,
                 "same_origin": sameorigin_summary,
                 "signer_disclosure": {
                     "self_attested": True,
                     "note": "signed with a self-attested certificate not yet "
                             "on the C2PA trust list; verifiers will report "
                             "the signer as untrusted until a CA-issued "
                             "certificate is in place",
                 },
                 "claims": {
                     "proves": ["custody", "integrity", "coherence", "priority"],
                     "does_not_prove": "authorship",
                 },
             }},
        ],
    }


def register(record_id: str, artist: str, master_path_in: Path,
             stem_paths_in: list[Path], project_zip_path: Path,
             master_name: str, user_id: str | None = None) -> dict:
    """Seal a QUEUED record whose inputs are already staged on local disk
    (the worker fetches them from the assets store first)."""
    watermark_hex = record_id.replace("-", "")
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    master = (master_name, master_path_in.read_bytes())
    stems = [(p.name, p.read_bytes()) for p in stem_paths_in]
    project_zip = project_zip_path.read_bytes()
    rec_dir = EVIDENCE / record_id
    (rec_dir / "originals").mkdir(parents=True, exist_ok=True)

    # preserve originals untouched (the evidence bundle)
    master_path = rec_dir / "originals" / (Path(master_name).name or "master.wav")
    master_path.write_bytes(master[1])
    logicx_path = rec_dir / "originals" / "project.zip"
    logicx_path.write_bytes(project_zip)
    stem_paths = []
    for i, s in enumerate(stems):
        p = rec_dir / "originals" / f"stem_{i}_{Path(s[0]).name}"
        p.write_bytes(s[1])
        stem_paths.append(p)

    # 1. verification layer
    sameorigin = same_origin.analyze(project_zip, stems, master)
    if "error" in sameorigin:
        shutil.rmtree(rec_dir, ignore_errors=True)
        raise RuntimeError(sameorigin["error"])
    coh = sameorigin["coherence"]

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # 2. watermark the master (payload = record id)
        norm = audio.decode_to_normalized_wav(master_path, tmp / "master_norm.wav")
        marked = rec_dir / "master_watermarked.wav"
        aw_embed(norm, marked, watermark_hex)
        got_hex, got_score = aw_extract(marked)
        if got_hex != watermark_hex:
            raise RuntimeError("watermark self-check failed after embedding")

        # 3. fingerprint the watermarked (distributed) master
        fp_raw, fp_seconds = fingerprint.compute_fingerprint(marked)
        fp_compressed = fingerprint.compute_compressed_fingerprint(marked)

        # 4. C2PA-sign the watermarked master
        stem_hashes = [{"filename": p.name, "sha256": hashing.sha256_file(p)}
                       for p in stem_paths]
        definition = _build_manifest(
            record_id, created_at,
            master_sha=hashing.sha256_file(master_path),
            signed_source_sha=hashing.sha256_file(marked),
            logicx_sha=hashing.sha256_file(logicx_path),
            stem_hashes=stem_hashes,
            fp_compressed=fp_compressed, fp_seconds=fp_seconds,
            watermark_hex=watermark_hex,
            coherence=coh,
            sameorigin_summary={"score": sameorigin["score"],
                                "band": sameorigin["band"],
                                "red_flags": sameorigin["red_flags"]},
        )
        signed_path, _, report = manifest.sign(marked, definition,
                                               rec_dir / "manifest")

    (rec_dir / "same_origin_report.json").write_text(json.dumps(sameorigin, indent=2))

    # publish the public manifest (S3 manifests bucket / local stand-in)
    manifest_doc = {
        "record_id": record_id,
        "artist": artist,
        "sealed_at_utc": created_at,
        "cert_subject": manifest.cert_subject(),
        "self_attested": True,
        # published copy MUST NOT include the signing key/cert paths
        "manifest": manifest.published_view(definition),
    }
    manifest_key, manifest_url = store.put_manifest(manifest_doc, record_id)

    pg.update_record_sealed(
        record_id=record_id, sealed_at=created_at,
        selfcheck=round(got_score, 3),
        fp_raw=fp_raw, fp_seconds=fp_seconds,
        coherence=coh, sameorigin=sameorigin,
        master_sha=hashing.sha256_file(master_path),
        release_master_sha=hashing.sha256_file(rec_dir / "master_watermarked.wav"),
        project_sha=hashing.sha256_file(logicx_path),
        manifest=definition, cert_subject=manifest.cert_subject(),
        signed_asset_path=str(signed_path),
        manifest_s3_key=manifest_key, manifest_public_url=manifest_url)

    # stage the release master in the assets store (heimdall serves or
    # presigns it via the RELEASE_MASTER asset row)
    owner = user_id or pg.poc_user_id()
    release_asset_id = str(uuid.uuid4())
    release_key = f"{owner}/{record_id}/{release_asset_id}.wav"
    store.put_asset(signed_path, release_key)
    pg.insert_asset(owner_user_id=owner, record_id=record_id,
                    kind="RELEASE_MASTER", bucket=store.assets_bucket(),
                    key=release_key, content_type="audio/wav",
                    size_bytes=signed_path.stat().st_size,
                    sha256=hashing.sha256_file(signed_path),
                    original_filename=f"{Path(master_name).stem}_watermarked_signed.wav")
    pg.mark_record_assets_attached(record_id)

    downloads = {"signed_master": {
        "url": f"/records/{record_id}/release",
        "filename": f"{Path(master_name).stem}_watermarked_signed.wav",
        "size_bytes": signed_path.stat().st_size,
    }}

    return {
        "record_id": record_id,
        "artist": artist,
        "created_at_utc": created_at,
        "downloads": downloads,
        "coherence": coh,
        "same_origin": sameorigin,
        "watermark": {"algorithm": "audiowmark", "payload_hex": watermark_hex,
                      "self_check_score": round(got_score, 2)},
        "fingerprint": {"algorithm": "chromaprint", "frames": len(fp_raw),
                        "seconds": fp_seconds},
        "c2pa": {
            "signed": True,
            "signature_alg": manifest.SIGNATURE_ALG,
            "cert_subject": manifest.cert_subject(),
            "self_attested": True,
            "logicx_hard_binding": "signed SHA-256 commitment in the manifest",
            "trust_note": "self-attested certificate not yet on the C2PA "
                          "trust list; verifiers report "
                          "signingCredential.untrusted until a CA cert is set",
        },
        "signed_asset": str(signed_path),
        "proves": "custody, integrity, coherence, priority",
        "does_not_prove": "authorship",
    }
