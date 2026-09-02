"""Thor — the seal worker.

Polls the jobs table (SKIP LOCKED claim; the DB is the source of truth,
SQS arrives later as the delivery nudge) and runs the full sealing
pipeline for each SEAL job. Run from the service root:

    .venv/bin/python -m app.worker
"""

import os
import socket
import sys
import time
import traceback
from pathlib import Path

from . import pg, product

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "2"))


def process(job: dict) -> dict:
    p = job["payload"]
    return product.register(
        record_id=str(job["record_id"]),
        artist=p["artist"],
        master_path_in=Path(p["master_path"]),
        stem_paths_in=[Path(s) for s in p["stem_paths"]],
        project_zip_path=Path(p["project_zip_path"]),
        master_name=p["master_name"],
    )


def main() -> None:
    print(f"[thor {WORKER_ID}] polling every {POLL_SECONDS}s", flush=True)
    while True:
        job = pg.claim_next_job(WORKER_ID)
        if job is None:
            time.sleep(POLL_SECONDS)
            continue
        rid = str(job["record_id"])
        print(f"[thor] claimed job {job['id']} record {rid} "
              f"(attempt {job['attempts']})", flush=True)
        t0 = time.time()
        try:
            result = process(job)
            pg.complete_job(job["id"], result)
            print(f"[thor] sealed {rid} in {time.time() - t0:.1f}s", flush=True)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            retry = job["attempts"] < job["max_attempts"]
            pg.fail_job(job["id"], rid, err, retry=retry)
            print(f"[thor] job {job['id']} failed "
                  f"({'will retry' if retry else 'FINAL'}): {err}",
                  file=sys.stderr, flush=True)
            traceback.print_exc()


if __name__ == "__main__":
    main()
