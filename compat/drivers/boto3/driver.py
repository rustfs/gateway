"""boto3 scenario driver.

Responsible for: turning one abstract scenario into boto3 calls and printing one result object.
NOT responsible for: judging wire facts. The system under test records those, and
`ci/compat/report.py` evaluates them; a driver that graded its own wire behaviour would be
reporting its intention rather than an observation.
Upstream: `ci/compat/run_matrix.sh`. Downstream: `ci/compat/report.py`.
"""

import json
import os
import sys
import urllib.error
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = os.environ["COMPAT_ENDPOINT"]
BUCKET = os.environ["COMPAT_BUCKET"]
WORKDIR = os.environ["COMPAT_WORKDIR"]


def client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id=os.environ["COMPAT_ACCESS_KEY"],
        aws_secret_access_key=os.environ["COMPAT_SECRET_KEY"],
        region_name=os.environ["COMPAT_REGION"],
        config=Config(
            s3={"addressing_style": "path"},
            signature_version="s3v4",
            retries={"max_attempts": 1},
        ),
    )


def emit(scenario, status, detail="", evidence=None):
    print(json.dumps({"scenario": scenario, "status": status, "detail": detail, "evidence": evidence or {}}))
    raise SystemExit(0)


def make_bucket(s3):
    s3.create_bucket(Bucket=BUCKET)


def drop_bucket(s3, keys=()):
    for key in keys:
        try:
            s3.delete_object(Bucket=BUCKET, Key=key)
        except ClientError:
            pass
    try:
        s3.delete_bucket(Bucket=BUCKET)
    except ClientError:
        pass


def scenario_bucket_lifecycle(s3, scenario):
    make_bucket(s3)
    s3.head_bucket(Bucket=BUCKET)
    s3.delete_bucket(Bucket=BUCKET)
    try:
        s3.head_bucket(Bucket=BUCKET)
    except ClientError as error:
        emit(scenario, "pass", "", {"deleted_bucket_status": error.response["ResponseMetadata"]["HTTPStatusCode"]})
    emit(scenario, "fail", "the bucket answered HeadBucket after it was deleted")


def scenario_small_object_roundtrip(s3, scenario):
    payload = os.urandom(4096)
    make_bucket(s3)
    try:
        s3.put_object(Bucket=BUCKET, Key="small.bin", Body=payload)
        read = s3.get_object(Bucket=BUCKET, Key="small.bin")["Body"].read()
        head = s3.head_object(Bucket=BUCKET, Key="small.bin")
        if read != payload:
            emit(scenario, "fail", f"read back {len(read)} bytes that differ from the {len(payload)} written")
        if head["ContentLength"] != len(payload):
            emit(scenario, "fail", f"HeadObject reported {head['ContentLength']} for a {len(payload)} byte object")
        emit(scenario, "pass", "", {"etag": head["ETag"]})
    finally:
        drop_bucket(s3, ["small.bin"])


def scenario_large_multipart_upload(s3, scenario):
    from boto3.s3.transfer import TransferConfig

    payload = os.urandom(12 * 1024 * 1024)
    source = os.path.join(WORKDIR, "multipart.bin")
    with open(source, "wb") as handle:
        handle.write(payload)
    make_bucket(s3)
    try:
        s3.upload_file(
            source,
            BUCKET,
            "multipart.bin",
            Config=TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024),
        )
        head = s3.head_object(Bucket=BUCKET, Key="multipart.bin")
        read = s3.get_object(Bucket=BUCKET, Key="multipart.bin")["Body"].read()
        if read != payload:
            emit(scenario, "fail", f"read back {len(read)} bytes that differ from the {len(payload)} written")
        if "-" not in head["ETag"]:
            emit(scenario, "fail", f"a multipart object reported a single-part entity tag {head['ETag']}")
        emit(scenario, "pass", "", {"etag": head["ETag"]})
    finally:
        drop_bucket(s3, ["multipart.bin"])


def scenario_list_pagination(s3, scenario):
    keys = [f"page/{index:04d}.txt" for index in range(25)]
    make_bucket(s3)
    try:
        for key in keys:
            s3.put_object(Bucket=BUCKET, Key=key, Body=key.encode())
        seen = []
        pages = 0
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=BUCKET, PaginationConfig={"PageSize": 7}):
            pages += 1
            seen.extend(entry["Key"] for entry in page.get("Contents", []))
        if sorted(seen) != sorted(keys):
            emit(scenario, "fail", f"listed {len(seen)} distinct keys over {pages} page(s), expected {len(keys)}")
        if pages < 2:
            emit(scenario, "fail", f"a {len(keys)} key listing at page size 7 returned {pages} page(s)")
        emit(scenario, "pass", "", {"pages": pages, "keys": len(seen)})
    finally:
        drop_bucket(s3, keys)


def scenario_range_download(s3, scenario):
    payload = os.urandom(1024 * 1024)
    start, end = 1000, 5000
    make_bucket(s3)
    try:
        s3.put_object(Bucket=BUCKET, Key="ranged.bin", Body=payload)
        response = s3.get_object(Bucket=BUCKET, Key="ranged.bin", Range=f"bytes={start}-{end}")
        read = response["Body"].read()
        expected = payload[start : end + 1]
        status = response["ResponseMetadata"]["HTTPStatusCode"]
        if read != expected:
            emit(
                scenario,
                "fail",
                f"a bytes={start}-{end} request answered {status} with {len(read)} bytes, expected 206 with {len(expected)}",
                {"status": status, "returned_bytes": len(read), "expected_bytes": len(expected)},
            )
        emit(scenario, "pass", "", {"status": status, "returned_bytes": len(read)})
    finally:
        drop_bucket(s3, ["ranged.bin"])


def _fetch(request):
    try:
        with urllib.request.urlopen(request) as response:  # noqa: S310 - the endpoint is the local SUT
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def scenario_presigned_get(s3, scenario):
    payload = os.urandom(2048)
    make_bucket(s3)
    try:
        s3.put_object(Bucket=BUCKET, Key="presigned.bin", Body=payload)
        url = s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": "presigned.bin"}, ExpiresIn=300)
        status, body = _fetch(urllib.request.Request(url, method="GET"))
        if status != 200:
            emit(scenario, "fail", f"a presigned GET was answered {status}", {"status": status})
        if body != payload:
            emit(scenario, "fail", f"a presigned GET returned {len(body)} bytes, expected {len(payload)}")
        emit(scenario, "pass", "", {"status": status})
    finally:
        drop_bucket(s3, ["presigned.bin"])


def scenario_presigned_put(s3, scenario):
    payload = os.urandom(2048)
    make_bucket(s3)
    try:
        url = s3.generate_presigned_url("put_object", Params={"Bucket": BUCKET, "Key": "presigned-put.bin"}, ExpiresIn=300)
        status, body = _fetch(urllib.request.Request(url, data=payload, method="PUT"))
        if status not in (200, 201):
            emit(
                scenario,
                "fail",
                f"a presigned PUT was answered {status}",
                {"status": status, "body": body[:200].decode("utf-8", "replace")},
            )
        read = s3.get_object(Bucket=BUCKET, Key="presigned-put.bin")["Body"].read()
        if read != payload:
            emit(scenario, "fail", "a presigned PUT stored bytes that differ from the ones sent")
        emit(scenario, "pass", "", {"status": status})
    finally:
        drop_bucket(s3, ["presigned-put.bin"])


def scenario_versioned_object(s3, scenario):
    make_bucket(s3)
    try:
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        status = s3.get_bucket_versioning(Bucket=BUCKET).get("Status")
        if status != "Enabled":
            emit(scenario, "fail", f"versioning reported {status!r} after it was enabled")
        first = s3.put_object(Bucket=BUCKET, Key="versioned.bin", Body=b"first")
        second = s3.put_object(Bucket=BUCKET, Key="versioned.bin", Body=b"second")
        listing = s3.list_object_versions(Bucket=BUCKET, Prefix="versioned.bin")
        versions = [entry["VersionId"] for entry in listing.get("Versions", [])]
        if len(versions) < 2:
            emit(scenario, "fail", f"two writes to an enabled bucket enumerated {len(versions)} version(s)")
        oldest = s3.get_object(Bucket=BUCKET, Key="versioned.bin", VersionId=first["VersionId"])["Body"].read()
        if oldest != b"first":
            emit(scenario, "fail", "an explicit version read returned the wrong version's bytes")
        emit(scenario, "pass", "", {"versions": len(versions), "current": second["VersionId"]})
    finally:
        try:
            listing = s3.list_object_versions(Bucket=BUCKET)
            for entry in listing.get("Versions", []) + listing.get("DeleteMarkers", []):
                s3.delete_object(Bucket=BUCKET, Key=entry["Key"], VersionId=entry["VersionId"])
        except ClientError:
            pass
        drop_bucket(s3)


def scenario_copy_object(s3, scenario):
    make_bucket(s3)
    try:
        s3.put_object(Bucket=BUCKET, Key="source.bin", Body=b"copy me")
        s3.copy_object(Bucket=BUCKET, Key="target.bin", CopySource={"Bucket": BUCKET, "Key": "source.bin"})
        read = s3.get_object(Bucket=BUCKET, Key="target.bin")["Body"].read()
        if read != b"copy me":
            emit(scenario, "fail", "a server-side copy produced different bytes")
        emit(scenario, "pass")
    finally:
        drop_bucket(s3, ["source.bin", "target.bin"])


def scenario_delete_batch(s3, scenario):
    keys = [f"batch/{index}.txt" for index in range(10)]
    make_bucket(s3)
    try:
        for key in keys:
            s3.put_object(Bucket=BUCKET, Key=key, Body=b"x")
        s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": key} for key in keys]})
        remaining = s3.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0)
        if remaining:
            emit(scenario, "fail", f"{remaining} key(s) survived a batch delete")
        emit(scenario, "pass")
    finally:
        drop_bucket(s3, keys)


SCENARIOS = {
    "bucket-lifecycle": scenario_bucket_lifecycle,
    "small-object-roundtrip": scenario_small_object_roundtrip,
    "large-multipart-upload": scenario_large_multipart_upload,
    "list-pagination": scenario_list_pagination,
    "range-download": scenario_range_download,
    "presigned-get": scenario_presigned_get,
    "presigned-put": scenario_presigned_put,
    "versioned-object": scenario_versioned_object,
    "copy-object": scenario_copy_object,
    "delete-batch": scenario_delete_batch,
}

UNSUPPORTED = {
    "backup-restore": "boto3 is a client library, not a backup tool; it has no repository format to restore",
    "sync-directory": "boto3 offers no directory mirroring primitive; rclone and mc are the sync clients",
    # Measured, not assumed. Against a plaintext endpoint botocore's SigV4 signer hashes the whole
    # payload and sets that digest as x-amz-content-sha256; the aws-chunked wrapper it does own is
    # reached only on the unsigned-payload path, which requires TLS. Handing it a non-seekable body
    # to force the wrapper raises `UnsupportedOperation: seek` before a request is built, so there
    # is no boto3 call that produces chunked framing here. Recording that as a failure would blame
    # the server for a client's payload-mode choice.
    "streaming-chunked-upload": "botocore signs the whole payload over a plaintext endpoint and offers no switch that selects aws-chunked framing",
    "trailer-chunked-upload": "botocore emits a checksum header rather than a trailer unless the payload is unsigned, which it only is over TLS",
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
    s3 = client()
    try:
        handler(s3, scenario)
    except SystemExit:
        raise
    except ClientError as error:
        response = error.response
        code = response.get("Error", {}).get("Code", "?")
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        print(
            json.dumps(
                {
                    "scenario": scenario,
                    "status": "fail",
                    "detail": f"{code} ({status})",
                    "evidence": {"code": code, "status": status},
                }
            )
        )
    except Exception as error:  # noqa: BLE001 - a client crash is a scenario failure, not a runner failure
        print(
            json.dumps(
                {
                    "scenario": scenario,
                    "status": "fail",
                    "detail": f"{type(error).__name__}: {error}",
                    "evidence": {},
                }
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
