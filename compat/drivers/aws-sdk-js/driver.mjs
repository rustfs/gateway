// aws-sdk-js (v3) scenario driver.
//
// Responsible for: turning one abstract scenario into @aws-sdk/client-s3 calls on Node.js and
// printing one result object on stdout. NOT responsible for: judging wire facts; the system under
// test records those and ci/compat/report.py evaluates them. Upstream: ci/compat/run_matrix.sh via
// run.sh. Downstream: ci/compat/report.py.
//
// `node driver.mjs --client-version` prints the version of the @aws-sdk/client-s3 package this
// program resolves at runtime, read from that package's own manifest.

import { randomBytes } from "node:crypto";
import { createReadStream, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import {
  CopyObjectCommand,
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectsCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListObjectVersionsCommand,
  ListObjectsV2Command,
  PutBucketVersioningCommand,
  PutObjectCommand,
  S3Client,
  paginateListObjectsV2,
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const env = process.env;

class Outcome extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

const fail = (detail) => new Outcome("fail", detail);

function print(scenario, status, detail = "") {
  process.stdout.write(`${JSON.stringify({ scenario, status, detail, evidence: {} })}\n`);
}

function client(endpoint) {
  return new S3Client({
    endpoint,
    region: env.COMPAT_REGION,
    forcePathStyle: true,
    maxAttempts: 1,
    credentials: { accessKeyId: env.COMPAT_ACCESS_KEY, secretAccessKey: env.COMPAT_SECRET_KEY },
  });
}

const s3 = client(env.COMPAT_ENDPOINT);
const Bucket = env.COMPAT_BUCKET;

async function body(output) {
  return Buffer.from(await output.Body.transformToByteArray());
}

async function get(Key, extra = {}) {
  return body(await s3.send(new GetObjectCommand({ Bucket, Key, ...extra })));
}

async function put(Key, Body) {
  return s3.send(new PutObjectCommand({ Bucket, Key, Body }));
}

// A presigned URL is redeemed by Node's own fetch, not by the SDK: generation is the SDK's half and
// verification the server's.
async function redeem(url, init) {
  const response = await fetch(url, init);
  return { status: response.status, bytes: Buffer.from(await response.arrayBuffer()) };
}

const scenarios = {
  async "bucket-lifecycle"() {
    await s3.send(new HeadBucketCommand({ Bucket }));
    await s3.send(new DeleteBucketCommand({ Bucket }));
    try {
      await s3.send(new HeadBucketCommand({ Bucket }));
    } catch {
      return;
    }
    throw fail("the bucket answered HeadBucket after it was deleted");
  },

  async "small-object-roundtrip"() {
    const payload = randomBytes(4096);
    await put("small.bin", payload);
    const read = await get("small.bin");
    if (!read.equals(payload)) throw fail(`read back ${read.length} bytes that differ from the ${payload.length} written`);
    const head = await s3.send(new HeadObjectCommand({ Bucket, Key: "small.bin" }));
    if (head.ContentLength !== payload.length) {
      throw fail(`HeadObject reported ${head.ContentLength} for a ${payload.length} byte object`);
    }
  },

  async "large-multipart-upload"() {
    const payload = randomBytes(12 * 1024 * 1024);
    await new Upload({ client: s3, params: { Bucket, Key: "multipart.bin", Body: payload }, partSize: 5 * 1024 * 1024 }).done();
    const read = await get("multipart.bin");
    if (!read.equals(payload)) throw fail(`read back ${read.length} bytes that differ from the ${payload.length} written`);
    const head = await s3.send(new HeadObjectCommand({ Bucket, Key: "multipart.bin" }));
    if (!(head.ETag ?? "").includes("-")) throw fail(`a multipart object reported the single-part entity tag ${head.ETag}`);
  },

  async "list-pagination"() {
    const keys = Array.from({ length: 25 }, (_, index) => `page/${String(index).padStart(4, "0")}.txt`);
    for (const key of keys) await put(key, Buffer.from(key));
    const seen = [];
    let pages = 0;
    for await (const page of paginateListObjectsV2({ client: s3, pageSize: 7 }, { Bucket, Prefix: "page/" })) {
      pages += 1;
      for (const entry of page.Contents ?? []) seen.push(entry.Key);
      if (pages > 20) throw fail("the listing did not terminate within 20 pages");
    }
    seen.sort();
    if (seen.join(",") !== keys.join(",")) throw fail(`listed ${seen.length} keys over ${pages} page(s), expected ${keys.length}`);
    if (pages < 2) throw fail(`a ${keys.length} key listing at page size 7 returned ${pages} page(s)`);
  },

  async "range-download"() {
    const payload = randomBytes(1024 * 1024);
    await put("ranged.bin", payload);
    const read = await get("ranged.bin", { Range: "bytes=1000-5000" });
    if (!read.equals(payload.subarray(1000, 5001))) {
      throw fail(`bytes=1000-5000 returned ${read.length} bytes that differ from the same slice of the source`);
    }
  },

  async "presigned-get"() {
    const payload = randomBytes(2048);
    await put("presigned.bin", payload);
    const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket, Key: "presigned.bin" }), { expiresIn: 300 });
    const { status, bytes } = await redeem(url, { method: "GET" });
    if (status !== 200) throw fail(`a presigned GET was answered ${status}`);
    if (!bytes.equals(payload)) throw fail(`a presigned GET returned ${bytes.length} bytes, expected ${payload.length}`);
  },

  async "presigned-put"() {
    const payload = randomBytes(2048);
    const url = await getSignedUrl(s3, new PutObjectCommand({ Bucket, Key: "presigned-put.bin" }), { expiresIn: 300 });
    const { status } = await redeem(url, { method: "PUT", body: payload });
    if (status !== 200 && status !== 201) throw fail(`a presigned PUT was answered ${status}`);
    const read = await get("presigned-put.bin");
    if (!read.equals(payload)) throw fail("a presigned PUT stored bytes that differ from the ones sent");
  },

  async "versioned-object"() {
    await s3.send(new PutBucketVersioningCommand({ Bucket, VersioningConfiguration: { Status: "Enabled" } }));
    const { Status } = await s3.send(new GetBucketVersioningCommand({ Bucket }));
    if (Status !== "Enabled") throw fail(`versioning reported ${JSON.stringify(Status)} after it was enabled`);
    const first = await put("versioned.bin", Buffer.from("first"));
    await put("versioned.bin", Buffer.from("second"));
    const listing = await s3.send(new ListObjectVersionsCommand({ Bucket, Prefix: "versioned.bin" }));
    const count = (listing.Versions ?? []).length;
    if (count < 2) throw fail(`two writes to an enabled bucket enumerated ${count} version(s)`);
    const oldest = await get("versioned.bin", { VersionId: first.VersionId });
    if (oldest.toString() !== "first") throw fail("an explicit version read returned the wrong version's bytes");
  },

  async "copy-object"() {
    await put("source.bin", Buffer.from("copy me"));
    await s3.send(new CopyObjectCommand({ Bucket, Key: "target.bin", CopySource: `${Bucket}/source.bin` }));
    if ((await get("target.bin")).toString() !== "copy me") throw fail("a server-side copy produced different bytes");
  },

  async "delete-batch"() {
    const keys = Array.from({ length: 10 }, (_, index) => `batch/${index}.txt`);
    for (const key of keys) await put(key, Buffer.from("x"));
    await s3.send(new DeleteObjectsCommand({ Bucket, Delete: { Objects: keys.map((Key) => ({ Key })), Quiet: true } }));
    const listing = await s3.send(new ListObjectsV2Command({ Bucket }));
    if (listing.KeyCount !== 0) throw fail(`${listing.KeyCount} key(s) survived a batch delete`);
  },

  // Measured: given a file stream with a known length, the SDK frames it as aws-chunked with its
  // default CRC32 in an x-amz-trailer, over the plaintext endpoint as well as over TLS
  // (STREAMING-UNSIGNED-PAYLOAD-TRAILER). Nothing here asks for the trailer; whether one arrived is
  // the probe's call.
  async "trailer-chunked-upload"(work) {
    const payload = randomBytes(1024 * 1024);
    const source = path.join(work, "trailer.bin");
    writeFileSync(source, payload);
    await s3.send(
      new PutObjectCommand({ Bucket, Key: "trailer.bin", Body: createReadStream(source), ContentLength: payload.length }),
    );
    const read = await get("trailer.bin");
    if (!read.equals(payload)) throw fail(`read back ${read.length} bytes that differ from the ${payload.length} written`);
  },
};

const unsupported = {
  "backup-restore": "aws-sdk-js is an SDK, not a backup tool; it has no repository format to restore",
  "sync-directory": "aws-sdk-js offers no directory mirroring primitive",
  // Measured: a buffer body is sent with the whole-payload SHA-256 and a stream body as
  // STREAMING-UNSIGNED-PAYLOAD-TRAILER, on either endpoint; no chunk carries a signature, and the
  // SDK has no option that selects signed aws-chunked framing.
  "streaming-chunked-upload": "aws-sdk-js v3 frames streams as STREAMING-UNSIGNED-PAYLOAD-TRAILER and has no signed aws-chunked mode",
};

async function main() {
  const argument = process.argv[2];
  if (process.argv.length !== 3) {
    process.stderr.write("usage: driver.mjs <scenario-id> | --client-version\n");
    return 64;
  }
  if (argument === "--client-version") {
    const require = createRequire(import.meta.url);
    process.stdout.write(`${require("@aws-sdk/client-s3/package.json").version}\n`);
    return 0;
  }
  if (argument in unsupported) {
    print(argument, "unsupported", unsupported[argument]);
    return 0;
  }
  const run = scenarios[argument];
  if (!run) {
    process.stderr.write(`driver: unknown scenario ${argument}\n`);
    return 64;
  }
  try {
    await s3.send(new CreateBucketCommand({ Bucket }));
    await run(env.COMPAT_WORKDIR);
    print(argument, "pass");
  } catch (error) {
    if (error instanceof Outcome) {
      print(argument, error.status, error.detail);
    } else {
      const code = error?.Code ?? error?.name ?? "Error";
      print(argument, "fail", `${code}: ${error?.message ?? String(error)}`.slice(0, 500));
    }
  }
  return 0;
}

process.exitCode = await main();
