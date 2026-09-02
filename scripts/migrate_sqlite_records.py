"""One-time migration: SQLite product_records -> Postgres records.

Idempotent (ON CONFLICT DO NOTHING on id). Run from Backend/:
    .venv/bin/python -m scripts.migrate_sqlite_records
"""

import json
import sqlite3
from pathlib import Path

from app import pg

SQLITE = Path(__file__).resolve().parent.parent / "provenance.db"


def main():
    conn = sqlite3.connect(SQLITE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM product_records").fetchall()
    conn.close()

    user_id = pg.poc_user_id()
    migrated = skipped = 0
    with pg.pool().connection() as pgc:
        for r in rows:
            manifest = json.loads(r["manifest_json"])
            record_assertion = next(
                (a["data"] for a in manifest.get("assertions", [])
                 if a.get("label", "").endswith(".record")), {})
            release_sha = (record_assertion.get("master") or {}).get(
                "watermarked_sha256")
            res = pgc.execute(
                """insert into records
                     (id, user_id, artist_name, status, daw,
                      watermark_payload, fingerprint, fingerprint_seconds,
                      coherence_verified, coherence_confidence,
                      sameorigin_score, sameorigin_band,
                      master_sha256, release_master_sha256, project_sha256,
                      manifest, cert_subject, sealed_at, meta)
                   values (%s, %s, %s, 'SEALED', 'LOGIC_PRO',
                           %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s)
                   on conflict (id) do nothing""",
                (r["id"], user_id, r["artist"],
                 r["watermark_hex"],
                 pg.pack_fingerprint(json.loads(r["fingerprint_raw"])),
                 r["fingerprint_seconds"],
                 bool(r["coherence_verified"]), r["coherence_confidence"],
                 r["sameorigin_score"], r["sameorigin_band"].upper(),
                 r["master_sha256"], release_sha, r["logicx_sha256"],
                 pg.Jsonb(manifest), r["cert_subject"], r["created_at"],
                 pg.Jsonb({"signed_asset_path": r["signed_asset_path"],
                           "migrated_from": "sqlite"})))
            if res.rowcount:
                migrated += 1
            else:
                skipped += 1
    print(f"migrated {migrated}, already present {skipped}, total {len(rows)}")


if __name__ == "__main__":
    main()
