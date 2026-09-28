"""OpenDAL scenario driver.

Responsible for: turning one abstract scenario into OpenDAL operator calls (the Python binding over
the Rust `services-s3` backend) and printing one result object.
NOT responsible for: judging wire facts. The system under test records those, and
`ci/compat/report.py` evaluates them.
Upstream: `ci/compat/run_matrix.sh`. Downstream: `ci/compat/report.py`.

OpenDAL addresses objects inside one bucket and has no bucket operations at all. The bucket each
cell needs is therefore created, and removed, by boto3 (installed beside it by the same runner),
and those two requests are the only ones in a cell that did not come from OpenDAL. Everything the
scenario measures goes through the operator.
"""

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

import boto3
import opendal
from botocore.config import Config

ENDPOINT = os.environ["COMPAT_ENDPOINT"]
BUCKET = os.environ["COMPAT_BUCKET"]
REGION = os.environ["COMPAT_REGION"]
ACCESS_KEY = os.environ["COMPAT_ACCESS_KEY"]
SECRET_KEY = os.environ["COMPAT_SECRET_KEY"]

SETTINGS = {
    "bucket": BUCKET,
    "endpoint": ENDPOINT,
    "region": REGION,
    "access_key_id": ACCESS_KEY,
    "secret_access_key": SECRET_KEY,
}


def emit(scenario, status, detail="", evidence=None):
    print(json.dumps({"scenario": scenario, "status": status, "detail": detail, "evidence": evidence or {}}))
    raise SystemExit(0)


def bucket_admin():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name=REGION,
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4", retries={"max_attempts": 1}),
    )


def operator(**extra):
    return opendal.Operator("s3", **SETTINGS, **extra)


def scenario_small_object_roundtrip(op, scenario):
    payload = os.urandom(4096)
    op.write("small.bin", payload)
    read = op.read("small.bin")
    if bytes(read) != payload:
        emit(scenario, "fail", f"read back {len(read)} bytes that differ from the {len(payload)} written")
    length = op.stat("small.bin").content_length
    if length != len(payload):
        emit(scenario, "fail", f"stat reported {length} for a {len(payload)} byte object")
    emit(scenario, "pass")


def scenario_large_multipart_upload(op, scenario):
    payload = os.urandom(12 * 1024 * 1024)
    # A 5 MiB write chunk makes the writer send a multipart upload; the part count is the client's.
    op.write("multipart.bin", payload, chunk=5 * 1024 * 1024)
    read = op.read("multipart.bin")
    if bytes(read) != payload:
        emit(scenario, "fail", f"read back {len(read)} bytes that differ from the {len(payload)} written")
    etag = op.stat("multipart.bin").etag or ""
    if "-" not in etag:
        emit(scenario, "fail", f"a chunked write of {len(payload)} bytes reported the single-part entity tag {etag}")
    emit(scenario, "pass")


def scenario_list_pagination(op, scenario):
    keys = [f"page/{index:04d}.txt" for index in range(25)]
    for key in keys:
        op.write(key, key.encode())
    # `limit` is the page size OpenDAL asks the server for; the lister follows continuation tokens.
    seen = sorted(entry.path for entry in op.list("page/", limit=7) if not entry.path.endswith("/"))
    if seen != keys:
        emit(scenario, "fail", f"listed {len(seen)} keys at 7 per page, expected {len(keys)}")
    emit(scenario, "pass")


def scenario_range_download(op, scenario):
    payload = os.urandom(1024 * 1024)
    op.write("ranged.bin", payload)
    read = bytes(op.read("ranged.bin", offset=1000, size=4001))
    if read != payload[1000:5001]:
        emit(scenario, "fail", f"offset 1000 size 4001 returned {len(read)} bytes that differ from the same slice")
    emit(scenario, "pass")


def _fetch(request):
    try:
        with urllib.request.urlopen(request) as response:  # noqa: S310 - the endpoint is the local SUT
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def presign(kind, path):
    # The async operator is the binding's only presigning surface, and it must be built inside the
    # event loop that awaits it.
    async def run():
        return await getattr(opendal.AsyncOperator("s3", **SETTINGS), kind)(path, 300)

    return asyncio.run(run())


def _request(presigned, data=None):
    return urllib.request.Request(presigned.url, data=data, method=presigned.method, headers=dict(presigned.headers))


def scenario_presigned_get(op, scenario):
    payload = os.urandom(2048)
    op.write("presigned.bin", payload)
    presigned = presign("presign_read", "presigned.bin")
    status, body = _fetch(_request(presigned))
    if status != 200:
        emit(scenario, "fail", f"a presigned GET was answered {status}", {"status": status})
    if body != payload:
        emit(scenario, "fail", f"a presigned GET returned {len(body)} bytes, expected {len(payload)}")
    emit(scenario, "pass")


def scenario_presigned_put(op, scenario):
    payload = os.urandom(2048)
    presigned = presign("presign_write", "presigned-put.bin")
    status, _ = _fetch(_request(presigned, payload))
    if status not in (200, 201):
        emit(scenario, "fail", f"a presigned PUT was answered {status}", {"status": status})
    if bytes(op.read("presigned-put.bin")) != payload:
        emit(scenario, "fail", "a presigned PUT stored bytes that differ from the ones sent")
    emit(scenario, "pass")


def scenario_copy_object(op, scenario):
    op.write("source.bin", b"copy me")
    op.copy("source.bin", "target.bin")
    if bytes(op.read("target.bin")) != b"copy me":
        emit(scenario, "fail", "a server-side copy produced different bytes")
    emit(scenario, "pass")


def scenario_delete_batch(op, scenario):
    keys = [f"batch/{index}.txt" for index in range(10)]
    for key in keys:
        op.write(key, b"x")
    # A recursive delete is batched by the S3 backend into DeleteObjects requests.
    op.delete("batch/", recursive=True)
    remaining = [entry.path for entry in op.list("batch/", recursive=True) if not entry.path.endswith("/")]
    if remaining:
        emit(scenario, "fail", f"{len(remaining)} key(s) survived a batch delete")
    emit(scenario, "pass")


def scenario_versioned_object(op, scenario):
    bucket_admin().put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    op.write("versioned.bin", b"first")
    first = op.stat("versioned.bin").version
    op.write("versioned.bin", b"second")
    if not first:
        emit(scenario, "fail", "a write to a versioning-enabled bucket reported no version id")
    versions = [entry for entry in op.list("versioned.bin", versions=True) if entry.path == "versioned.bin"]
    if len(versions) < 2:
        emit(scenario, "fail", f"two writes to an enabled bucket enumerated {len(versions)} version(s)")
    if bytes(op.read("versioned.bin", version=first)) != b"first":
        emit(scenario, "fail", "an explicit version read returned the wrong version's bytes")
    emit(scenario, "pass")


SCENARIOS = {
    "small-object-roundtrip": scenario_small_object_roundtrip,
    "large-multipart-upload": scenario_large_multipart_upload,
    "list-pagination": scenario_list_pagination,
    "range-download": scenario_range_download,
    "presigned-get": scenario_presigned_get,
    "presigned-put": scenario_presigned_put,
    "copy-object": scenario_copy_object,
    "delete-batch": scenario_delete_batch,
    "versioned-object": scenario_versioned_object,
}

UNSUPPORTED = {
    "bucket-lifecycle": "OpenDAL addresses objects inside one configured bucket and has no bucket operations",
    "backup-restore": "OpenDAL is a storage access library, not a backup tool",
    "sync-directory": "OpenDAL offers no directory mirroring primitive",
    # Measured: the S3 backend declares UNSIGNED-PAYLOAD for writes over a plaintext endpoint and
    # never frames a body as aws-chunked, so neither chunked scenario is expressible.
    "streaming-chunked-upload": "OpenDAL's S3 backend declares UNSIGNED-PAYLOAD for writes and has no aws-chunked mode",
    "trailer-chunked-upload": "OpenDAL's S3 backend sends no trailing checksum; it has no aws-chunked mode",
}


def main():
    if len(sys.argv) != 2:
        print("usage: driver.py <scenario-id>", file=sys.stderr)
        return 64
    scenario = sys.argv[1]
    if scenario in UNSUPPORTED:
        print(json.dumps({"scenario": scenario, "status": "unsupported", "detail": UNSUPPORTED[scenario], "evidence": {}}))
        return 0
    handler = SCENARIOS.get(scenario)
    if handler is None:
        print(f"driver: unknown scenario {scenario}", file=sys.stderr)
        return 64
    admin = bucket_admin()
    admin.create_bucket(Bucket=BUCKET)
    try:
        handler(operator(), scenario)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - a client error is a scenario failure, not a runner failure
        print(json.dumps({"scenario": scenario, "status": "fail", "detail": f"{type(error).__name__}: {error}"[:500], "evidence": {}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
