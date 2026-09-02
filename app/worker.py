"""Thor — the seal worker.

The jobs table is the source of truth; SQS is the delivery nudge.
The loop long-polls SQS (which doubles as the idle sleep) and, whenever
nudged — or on a fallback cadence, so lost messages only cost latency —
drains every QUEUED job via an atomic SKIP LOCKED claim. Messages are
deleted on receipt: they carry no state, the DB does. Run:

    .venv/bin/python -m app.worker
"""

import json
import os
import socket
import sys
import time
import traceback
from pathlib import Path

from . import pg, product  # pg loads .env before boto3 reads the environment

import boto3

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"
SQS_URL = os.environ.get("SQS_SEAL_QUEUE_URL")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "2"))
FALLBACK_POLL_SECONDS = float(os.environ.get("FALLBACK_POLL_SECONDS", "30"))

_sqs = (boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
        if SQS_URL else None)


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


def drain_queued_jobs() -> int:
    """Claim and process QUEUED jobs until none remain. Returns count."""
    done = 0
    while True:
        try:
            job = pg.claim_next_job(WORKER_ID)
        except Exception as e:
            # DB restarts and blips must never kill the worker.
            print(f"[thor] db unavailable, retrying: {e}",
                  file=sys.stderr, flush=True)
            time.sleep(POLL_SECONDS * 2)
            return done
        if job is None:
            return done
        rid = str(job["record_id"])
        print(f"[thor] claimed job {job['id']} record {rid} "
              f"(attempt {job['attempts']})", flush=True)
        t0 = time.time()
        try:
            result = process(job)
            pg.complete_job(job["id"], result)
            done += 1
            print(f"[thor] sealed {rid} in {time.time() - t0:.1f}s", flush=True)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            retry = job["attempts"] < job["max_attempts"]
            pg.fail_job(job["id"], rid, err, retry=retry)
            print(f"[thor] job {job['id']} failed "
                  f"({'will retry' if retry else 'FINAL'}): {err}",
                  file=sys.stderr, flush=True)
            traceback.print_exc()


def wait_for_nudge() -> bool:
    """Long-poll SQS (doubles as the idle sleep). True if nudged."""
    try:
        resp = _sqs.receive_message(QueueUrl=SQS_URL, MaxNumberOfMessages=10,
                                    WaitTimeSeconds=20)
    except Exception as e:
        print(f"[thor] sqs receive failed, falling back to db poll: {e}",
              file=sys.stderr, flush=True)
        time.sleep(5)
        return False
    msgs = resp.get("Messages", [])
    for m in msgs:
        # The message is only a wake-up signal — delete immediately; the
        # fallback poll covers any message loss.
        try:
            _sqs.delete_message(QueueUrl=SQS_URL,
                                ReceiptHandle=m["ReceiptHandle"])
        except Exception:
            pass
    return bool(msgs)


def main() -> None:
    mode = f"sqs nudge + {FALLBACK_POLL_SECONDS:.0f}s db fallback" if _sqs \
        else f"db poll every {POLL_SECONDS}s"
    print(f"[thor {WORKER_ID}] {mode}", flush=True)
    last_fallback = 0.0
    while True:
        if _sqs is None:
            if drain_queued_jobs() == 0:
                time.sleep(POLL_SECONDS)
            continue
        nudged = wait_for_nudge()
        if nudged or time.time() - last_fallback >= FALLBACK_POLL_SECONDS:
            last_fallback = time.time()
            drain_queued_jobs()


if __name__ == "__main__":
    main()
