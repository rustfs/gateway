// aws-sdk-java-v2 scenario driver.
//
// Responsible for: turning one abstract scenario into AWS SDK for Java 2.x calls and printing one
// result object on stdout. NOT responsible for: judging wire facts; the system under test records
// those and ci/compat/report.py evaluates them. Upstream: ci/compat/run_matrix.sh via run.sh.
// Downstream: ci/compat/report.py.
//
// `Driver --client-version` prints `VersionInfo.SDK_VERSION`, the version the linked sdk-core jar
// was built as, which is what the runner compares with the pin.
package compat;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.util.VersionInfo;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;

public final class Driver {
    private static final long MIB = 1024L * 1024L;

    private static final Map<String, String> UNSUPPORTED = Map.of(
            "backup-restore", "aws-sdk-java-v2 is an SDK, not a backup tool; it has no repository format to restore",
            "sync-directory", "aws-sdk-java-v2 offers no directory mirroring primitive");

    private static final List<String> SCENARIOS = List.of(
            "bucket-lifecycle", "small-object-roundtrip", "large-multipart-upload", "list-pagination",
            "range-download", "presigned-get", "presigned-put", "versioned-object", "copy-object",
            "delete-batch", "streaming-chunked-upload", "trailer-chunked-upload");

    // Headers java.net.http sets itself and refuses to accept from the caller.
    private static final Set<String> RESTRICTED = Set.of("host", "content-length", "connection", "expect", "upgrade");

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Ends a scenario early with a status other than pass; main prints it. */
    private static final class Outcome extends RuntimeException {
        final String status;

        Outcome(String status, String detail) {
            super(detail, null, false, false);
            this.status = status;
        }
    }

    private static Outcome fail(String format, Object... args) {
        return new Outcome("fail", String.format(format, args));
    }

    private final String endpoint = System.getenv("COMPAT_ENDPOINT");
    private final String bucket = System.getenv("COMPAT_BUCKET");
    private final Path work = Path.of(System.getenv("COMPAT_WORKDIR"));
    private final Region region = Region.of(System.getenv("COMPAT_REGION"));
    private final StaticCredentialsProvider credentials = StaticCredentialsProvider.create(
            AwsBasicCredentials.create(System.getenv("COMPAT_ACCESS_KEY"), System.getenv("COMPAT_SECRET_KEY")));
    private final S3Client s3;

    private Driver() {
        // The default synchronous client with its default HTTP client; only the endpoint, path-style
        // addressing, region, credentials and the retry budget are set.
        s3 = S3Client.builder()
                .endpointOverride(URI.create(endpoint))
                .forcePathStyle(true)
                .region(region)
                .credentialsProvider(credentials)
                .overrideConfiguration(o -> o.retryStrategy(AwsRetryStrategy.doNotRetry()))
                .build();
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: Driver <scenario-id> | --client-version");
            System.exit(64);
        }
        String scenario = args[0];
        if (scenario.equals("--client-version")) {
            System.out.println(VersionInfo.SDK_VERSION);
            return;
        }
        if (UNSUPPORTED.containsKey(scenario)) {
            print(scenario, "unsupported", UNSUPPORTED.get(scenario));
            return;
        }
        if (!SCENARIOS.contains(scenario)) {
            System.err.println("driver: unknown scenario " + scenario);
            System.exit(64);
        }
        String status = "pass";
        String detail = "";
        Driver d = null;
        try {
            d = new Driver();
            d.createBucket();
            d.run(scenario);
        } catch (Outcome early) {
            status = early.status;
            detail = early.getMessage();
        } catch (Exception | LinkageError error) {
            error.printStackTrace(System.err);
            status = "fail";
            detail = describe(error);
        } finally {
            if (d != null) {
                d.s3.close();
            }
        }
        print(scenario, status, detail);
        // The async multipart client's event loop threads are not daemons.
        System.exit(0);
    }

    private void createBucket() {
        s3.createBucket(b -> b.bucket(bucket));
    }

    private void run(String scenario) throws Exception {
        switch (scenario) {
            case "bucket-lifecycle" -> bucketLifecycle();
            case "small-object-roundtrip" -> smallObjectRoundtrip();
            case "large-multipart-upload" -> largeMultipartUpload();
            case "list-pagination" -> listPagination();
            case "range-download" -> rangeDownload();
            case "presigned-get" -> presignedGet();
            case "presigned-put" -> presignedPut();
            case "versioned-object" -> versionedObject();
            case "copy-object" -> copyObject();
            case "delete-batch" -> deleteBatch();
            case "streaming-chunked-upload" -> streamingChunkedUpload();
            case "trailer-chunked-upload" -> trailerChunkedUpload();
            default -> throw new IllegalStateException("no handler for " + scenario);
        }
    }

    private static void print(String scenario, String status, String detail) {
        System.out.println("{\"scenario\":" + quote(scenario) + ",\"status\":" + quote(status)
                + ",\"detail\":" + quote(detail == null ? "" : detail) + ",\"evidence\":{}}");
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    /** Names the server's answer when there was one, and the client's exception otherwise. */
    private static String describe(Throwable error) {
        Throwable cause = error;
        while ((cause instanceof CompletionException || cause instanceof ExecutionException) && cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (cause instanceof AwsServiceException service && service.awsErrorDetails() != null
                && service.awsErrorDetails().errorCode() != null) {
            return service.awsErrorDetails().errorCode() + ": " + service.awsErrorDetails().errorMessage();
        }
        return cause.toString();
    }

    private static byte[] random(int size) {
        byte[] payload = new byte[size];
        RANDOM.nextBytes(payload);
        return payload;
    }

    private byte[] get(String key, String range, String version) {
        ResponseBytes<GetObjectResponse> read = s3.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(bucket).key(key).range(range).versionId(version).build());
        return read.asByteArray();
    }

    private PutObjectResponse put(String key, byte[] body) {
        return s3.putObject(b -> b.bucket(bucket).key(key), RequestBody.fromBytes(body));
    }

    private void bucketLifecycle() {
        s3.headBucket(b -> b.bucket(bucket));
        s3.deleteBucket(b -> b.bucket(bucket));
        try {
            s3.headBucket(b -> b.bucket(bucket));
        } catch (AwsServiceException gone) {
            return;
        }
        throw fail("the bucket answered HeadBucket after it was deleted");
    }

    private void smallObjectRoundtrip() {
        byte[] payload = random(4096);
        put("small.bin", payload);
        byte[] read = get("small.bin", null, null);
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
        HeadObjectResponse head = s3.headObject(b -> b.bucket(bucket).key("small.bin"));
        if (head.contentLength() == null || head.contentLength() != payload.length) {
            throw fail("HeadObject reported %s for a %d byte object", head.contentLength(), payload.length);
        }
    }

    // The synchronous client has no transfer utility, so this uses the SDK's own multipart client:
    // S3AsyncClient with multipart enabled, which splits PutObject into
    // CreateMultipartUpload/UploadPart/CompleteMultipartUpload at the configured part size.
    // Measured: with defaults it initiates a CRC32 upload and sends every part as
    // STREAMING-UNSIGNED-PAYLOAD-TRAILER with the part's CRC32 in an x-amz-trailer, even over
    // plaintext, which is what a server must accept from this SDK against a real bucket.
    private void largeMultipartUpload() {
        byte[] payload = random((int) (12 * MIB));
        try (S3AsyncClient multipart = S3AsyncClient.builder()
                .endpointOverride(URI.create(endpoint))
                .forcePathStyle(true)
                .region(region)
                .credentialsProvider(credentials)
                .overrideConfiguration(o -> o.retryStrategy(AwsRetryStrategy.doNotRetry()))
                .multipartEnabled(true)
                .multipartConfiguration(c -> c.minimumPartSizeInBytes(5 * MIB).thresholdInBytes(5 * MIB))
                .build()) {
            multipart.putObject(b -> b.bucket(bucket).key("multipart.bin"), AsyncRequestBody.fromBytes(payload)).join();
        }
        byte[] read = get("multipart.bin", null, null);
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
        HeadObjectResponse head = s3.headObject(b -> b.bucket(bucket).key("multipart.bin"));
        if (head.eTag() == null || !head.eTag().contains("-")) {
            throw fail("a multipart object reported the single-part entity tag %s", head.eTag());
        }
    }

    private void listPagination() {
        List<String> keys = new ArrayList<>();
        for (int index = 0; index < 25; index++) {
            String key = String.format("page/%04d.txt", index);
            keys.add(key);
            put(key, key.getBytes());
        }
        List<String> seen = new ArrayList<>();
        int pages = 0;
        for (ListObjectsV2Response page : s3.listObjectsV2Paginator(b -> b.bucket(bucket).prefix("page/").maxKeys(7))) {
            pages++;
            for (S3Object entry : page.contents()) {
                seen.add(entry.key());
            }
            if (pages > 20) {
                throw fail("the listing did not terminate within 20 pages");
            }
        }
        Collections.sort(seen);
        if (!seen.equals(keys)) {
            throw fail("listed %d keys over %d page(s), expected %d", seen.size(), pages, keys.size());
        }
        if (pages < 2) {
            throw fail("a %d key listing at page size 7 returned %d page(s)", keys.size(), pages);
        }
    }

    private void rangeDownload() {
        byte[] payload = random((int) MIB);
        put("ranged.bin", payload);
        byte[] read = get("ranged.bin", "bytes=1000-5000", null);
        if (!Arrays.equals(read, Arrays.copyOfRange(payload, 1000, 5001))) {
            throw fail("bytes=1000-5000 returned %d bytes that differ from the same slice of the source", read.length);
        }
    }

    private S3Presigner presigner() {
        return S3Presigner.builder()
                .endpointOverride(URI.create(endpoint))
                .region(region)
                .credentialsProvider(credentials)
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build();
    }

    // Sends a presigned request with a plain HTTP client: generation is the SDK's half and
    // verification the server's, so the SDK must not be the one to send it. HTTP/1.1 is pinned
    // because java.net.http otherwise offers an h2c upgrade on a plaintext connection.
    private static HttpResponse<byte[]> redeem(String method, URI url, Map<String, List<String>> headers, byte[] body)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(url)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach((name, values) -> {
            if (!RESTRICTED.contains(name.toLowerCase())) {
                values.forEach(value -> request.header(name, value));
            }
        });
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        return client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private void presignedGet() throws Exception {
        byte[] payload = random(2048);
        put("presigned.bin", payload);
        PresignedGetObjectRequest presigned;
        try (S3Presigner presigner = presigner()) {
            presigned = presigner.presignGetObject(p -> p.signatureDuration(Duration.ofMinutes(5))
                    .getObjectRequest(g -> g.bucket(bucket).key("presigned.bin")));
        }
        HttpResponse<byte[]> response = redeem(presigned.httpRequest().method().name(), presigned.url().toURI(),
                presigned.signedHeaders(), null);
        if (response.statusCode() != 200) {
            throw fail("a presigned GET was answered %d", response.statusCode());
        }
        if (!Arrays.equals(response.body(), payload)) {
            throw fail("a presigned GET returned %d bytes, expected %d", response.body().length, payload.length);
        }
    }

    private void presignedPut() throws Exception {
        byte[] payload = random(2048);
        PresignedPutObjectRequest presigned;
        try (S3Presigner presigner = presigner()) {
            presigned = presigner.presignPutObject(p -> p.signatureDuration(Duration.ofMinutes(5))
                    .putObjectRequest(r -> r.bucket(bucket).key("presigned-put.bin")));
        }
        HttpResponse<byte[]> response = redeem(presigned.httpRequest().method().name(), presigned.url().toURI(),
                presigned.signedHeaders(), payload);
        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw fail("a presigned PUT was answered %d", response.statusCode());
        }
        if (!Arrays.equals(get("presigned-put.bin", null, null), payload)) {
            throw fail("a presigned PUT stored bytes that differ from the ones sent");
        }
    }

    private void versionedObject() {
        s3.putBucketVersioning(b -> b.bucket(bucket).versioningConfiguration(v -> v.status(BucketVersioningStatus.ENABLED)));
        BucketVersioningStatus status = s3.getBucketVersioning(b -> b.bucket(bucket)).status();
        if (status != BucketVersioningStatus.ENABLED) {
            throw fail("versioning reported \"%s\" after it was enabled", status == null ? "" : status);
        }
        PutObjectResponse first = put("versioned.bin", "first".getBytes());
        put("versioned.bin", "second".getBytes());
        ListObjectVersionsResponse listing = s3.listObjectVersions(b -> b.bucket(bucket).prefix("versioned.bin"));
        if (listing.versions().size() < 2) {
            throw fail("two writes to an enabled bucket enumerated %d version(s)", listing.versions().size());
        }
        if (!new String(get("versioned.bin", null, first.versionId())).equals("first")) {
            throw fail("an explicit version read returned the wrong version's bytes");
        }
    }

    private void copyObject() {
        put("source.bin", "copy me".getBytes());
        s3.copyObject(b -> b.sourceBucket(bucket).sourceKey("source.bin").destinationBucket(bucket).destinationKey("target.bin"));
        if (!new String(get("target.bin", null, null)).equals("copy me")) {
            throw fail("a server-side copy produced different bytes");
        }
    }

    private void deleteBatch() {
        List<ObjectIdentifier> objects = new ArrayList<>();
        for (int index = 0; index < 10; index++) {
            String key = "batch/" + index + ".txt";
            put(key, "x".getBytes());
            objects.add(ObjectIdentifier.builder().key(key).build());
        }
        s3.deleteObjects(b -> b.bucket(bucket).delete(d -> d.objects(objects).quiet(true)));
        ListObjectsV2Response listing = s3.listObjectsV2(b -> b.bucket(bucket));
        if (listing.keyCount() != null && listing.keyCount() != 0) {
            throw fail("%d key(s) survived a batch delete", listing.keyCount());
        }
    }

    // The SDK's ordinary file body with every default left alone. Measured: over plaintext the
    // default client frames it as aws-chunked with signed chunks and a CRC32 trailer
    // (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER); whether that arrived is the probe's call.
    private void streamingChunkedUpload() throws IOException {
        byte[] payload = random(9437184);
        Path file = work.resolve("streaming.bin");
        Files.write(file, payload);
        s3.putObject(b -> b.bucket(bucket).key("streaming.bin"), RequestBody.fromFile(file));
        byte[] read = get("streaming.bin", null, null);
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
    }

    // Measured: with default settings the SDK computes a CRC32 for every PutObject and, over
    // plaintext, carries it in an x-amz-trailer behind signed aws-chunked framing, so no TLS
    // endpoint and no explicit checksum option are needed. Nothing here writes the trailer.
    private void trailerChunkedUpload() {
        byte[] payload = random((int) MIB);
        put("trailer.bin", payload);
        byte[] read = get("trailer.bin", null, null);
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
    }
}
