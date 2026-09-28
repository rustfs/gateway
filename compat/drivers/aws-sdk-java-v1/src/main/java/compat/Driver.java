// aws-sdk-java-v1 scenario driver.
//
// Responsible for: turning one abstract scenario into AWS SDK for Java 1.x calls and printing one
// result object on stdout. NOT responsible for: judging wire facts; the system under test records
// those and ci/compat/report.py evaluates them. Upstream: ci/compat/run_matrix.sh via run.sh.
// Downstream: ci/compat/report.py.
//
// `Driver --client-version` prints `VersionInfoUtils.getVersion()`, read from the
// versionInfo.properties inside the linked aws-java-sdk-core jar, which the s3 artefact requires
// at its own exact release; that is what the runner compares with the pin.
package compat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.HttpMethod;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.BucketVersioningConfiguration;
import com.amazonaws.services.s3.model.DeleteObjectsRequest;
import com.amazonaws.services.s3.model.DeleteObjectsRequest.KeyVersion;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.ListVersionsRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.SetBucketVersioningConfigurationRequest;
import com.amazonaws.services.s3.model.VersionListing;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.amazonaws.util.IOUtils;
import com.amazonaws.util.VersionInfoUtils;

public final class Driver {
    private static final long MIB = 1024L * 1024L;

    private static final Map<String, String> UNSUPPORTED = Map.of(
            "backup-restore", "aws-sdk-java-v1 is an SDK, not a backup tool; it has no repository format to restore",
            "sync-directory", "aws-sdk-java-v1 offers no directory mirroring primitive",
            // Measured: 1.12.797's s3 and core jars contain no x-amz-trailer, no *-TRAILER payload
            // mode and no checksum-algorithm option anywhere; its PutObject over plaintext is
            // STREAMING-AWS4-HMAC-SHA256-PAYLOAD with no trailer, and its only integrity header is
            // Content-MD5. The trailer form arrived with flexible checksums in the 2.x SDK.
            "trailer-chunked-upload", "aws-sdk-java-v1 predates flexible checksums and has no way to declare an x-amz-trailer");

    private static final List<String> SCENARIOS = List.of(
            "bucket-lifecycle", "small-object-roundtrip", "large-multipart-upload", "list-pagination",
            "range-download", "presigned-get", "presigned-put", "versioned-object", "copy-object",
            "delete-batch", "streaming-chunked-upload");

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

    private final String bucket = System.getenv("COMPAT_BUCKET");
    private final Path work = Path.of(System.getenv("COMPAT_WORKDIR"));
    private final AmazonS3 s3;

    private Driver() {
        // The builder's defaults with only the endpoint, path-style addressing, region, credentials
        // and the retry budget set. Region and endpoint together select SigV4 for requests and
        // presigned URLs alike.
        s3 = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(new EndpointConfiguration(System.getenv("COMPAT_ENDPOINT"), System.getenv("COMPAT_REGION")))
                .withPathStyleAccessEnabled(true)
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials(System.getenv("COMPAT_ACCESS_KEY"), System.getenv("COMPAT_SECRET_KEY"))))
                .withClientConfiguration(new ClientConfiguration().withMaxErrorRetry(0))
                .build();
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: Driver <scenario-id> | --client-version");
            System.exit(64);
        }
        String scenario = args[0];
        if (scenario.equals("--client-version")) {
            System.out.println(VersionInfoUtils.getVersion());
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
            d.s3.createBucket(d.bucket);
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
                d.s3.shutdown();
            }
        }
        print(scenario, status, detail);
        // The client's connection reaper and TransferManager's pool must not hold the JVM open.
        System.exit(0);
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
        // TransferManager wraps the part upload's failure; the server's answer is underneath.
        while (!(cause instanceof AmazonServiceException) && cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (cause instanceof AmazonServiceException service && service.getErrorCode() != null) {
            return service.getErrorCode() + ": " + service.getErrorMessage();
        }
        return error.toString();
    }

    private static byte[] random(int size) {
        byte[] payload = new byte[size];
        RANDOM.nextBytes(payload);
        return payload;
    }

    private byte[] get(GetObjectRequest request) throws IOException {
        try (S3Object object = s3.getObject(request)) {
            return IOUtils.toByteArray(object.getObjectContent());
        }
    }

    private byte[] get(String key) throws IOException {
        return get(new GetObjectRequest(bucket, key));
    }

    private PutObjectResult put(String key, byte[] body) {
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(body.length);
        return s3.putObject(bucket, key, new ByteArrayInputStream(body), metadata);
    }

    private void bucketLifecycle() {
        s3.headBucket(new HeadBucketRequest(bucket));
        s3.deleteBucket(bucket);
        try {
            s3.headBucket(new HeadBucketRequest(bucket));
        } catch (AmazonServiceException gone) {
            return;
        }
        throw fail("the bucket answered HeadBucket after it was deleted");
    }

    private void smallObjectRoundtrip() throws IOException {
        byte[] payload = random(4096);
        put("small.bin", payload);
        byte[] read = get("small.bin");
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
        long length = s3.getObjectMetadata(bucket, "small.bin").getContentLength();
        if (length != payload.length) {
            throw fail("HeadObject reported %d for a %d byte object", length, payload.length);
        }
    }

    // TransferManager is v1's multipart utility; the threshold and minimum part size make it split
    // the 12 MiB body into 5 MiB parts.
    private void largeMultipartUpload() throws Exception {
        byte[] payload = random((int) (12 * MIB));
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(payload.length);
        TransferManager transfers = TransferManagerBuilder.standard()
                .withS3Client(s3)
                .withMultipartUploadThreshold(5 * MIB)
                .withMinimumUploadPartSize(5 * MIB)
                .build();
        try {
            transfers.upload(bucket, "multipart.bin", new ByteArrayInputStream(payload), metadata).waitForCompletion();
        } finally {
            transfers.shutdownNow(false);
        }
        byte[] read = get("multipart.bin");
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
        String etag = s3.getObjectMetadata(bucket, "multipart.bin").getETag();
        if (etag == null || !etag.contains("-")) {
            throw fail("a multipart object reported the single-part entity tag %s", etag);
        }
    }

    // v1 has no paginator; the continuation token is followed by hand, as its documentation shows.
    private void listPagination() {
        List<String> keys = new ArrayList<>();
        for (int index = 0; index < 25; index++) {
            String key = String.format("page/%04d.txt", index);
            keys.add(key);
            put(key, key.getBytes());
        }
        List<String> seen = new ArrayList<>();
        int pages = 0;
        ListObjectsV2Request request = new ListObjectsV2Request().withBucketName(bucket).withPrefix("page/").withMaxKeys(7);
        ListObjectsV2Result page;
        do {
            page = s3.listObjectsV2(request);
            pages++;
            for (S3ObjectSummary entry : page.getObjectSummaries()) {
                seen.add(entry.getKey());
            }
            if (pages > 20) {
                throw fail("the listing did not terminate within 20 pages");
            }
            request.setContinuationToken(page.getNextContinuationToken());
        } while (page.isTruncated());
        Collections.sort(seen);
        if (!seen.equals(keys)) {
            throw fail("listed %d keys over %d page(s), expected %d", seen.size(), pages, keys.size());
        }
        if (pages < 2) {
            throw fail("a %d key listing at page size 7 returned %d page(s)", keys.size(), pages);
        }
    }

    private void rangeDownload() throws IOException {
        byte[] payload = random((int) MIB);
        put("ranged.bin", payload);
        byte[] read = get(new GetObjectRequest(bucket, "ranged.bin").withRange(1000, 5000));
        if (!Arrays.equals(read, Arrays.copyOfRange(payload, 1000, 5001))) {
            throw fail("bytes=1000-5000 returned %d bytes that differ from the same slice of the source", read.length);
        }
    }

    private URL presign(String key, HttpMethod method) {
        return s3.generatePresignedUrl(new GeneratePresignedUrlRequest(bucket, key, method)
                .withExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000)));
    }

    // Sends a presigned request with a plain HTTP client: generation is the SDK's half and
    // verification the server's, so the SDK must not be the one to send it. v1 presigns no headers
    // beyond host, so the URL is all there is to carry. HTTP/1.1 is pinned because java.net.http
    // otherwise offers an h2c upgrade on a plaintext connection.
    private static HttpResponse<byte[]> redeem(String method, URL url, byte[] body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(url.toURI())
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        return client.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private void presignedGet() throws Exception {
        byte[] payload = random(2048);
        put("presigned.bin", payload);
        HttpResponse<byte[]> response = redeem("GET", presign("presigned.bin", HttpMethod.GET), null);
        if (response.statusCode() != 200) {
            throw fail("a presigned GET was answered %d", response.statusCode());
        }
        if (!Arrays.equals(response.body(), payload)) {
            throw fail("a presigned GET returned %d bytes, expected %d", response.body().length, payload.length);
        }
    }

    private void presignedPut() throws Exception {
        byte[] payload = random(2048);
        HttpResponse<byte[]> response = redeem("PUT", presign("presigned-put.bin", HttpMethod.PUT), payload);
        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw fail("a presigned PUT was answered %d", response.statusCode());
        }
        if (!Arrays.equals(get("presigned-put.bin"), payload)) {
            throw fail("a presigned PUT stored bytes that differ from the ones sent");
        }
    }

    private void versionedObject() throws IOException {
        s3.setBucketVersioningConfiguration(new SetBucketVersioningConfigurationRequest(bucket,
                new BucketVersioningConfiguration(BucketVersioningConfiguration.ENABLED)));
        String status = s3.getBucketVersioningConfiguration(bucket).getStatus();
        if (!BucketVersioningConfiguration.ENABLED.equals(status)) {
            throw fail("versioning reported \"%s\" after it was enabled", status);
        }
        PutObjectResult first = put("versioned.bin", "first".getBytes());
        put("versioned.bin", "second".getBytes());
        VersionListing listing = s3.listVersions(new ListVersionsRequest().withBucketName(bucket).withPrefix("versioned.bin"));
        if (listing.getVersionSummaries().size() < 2) {
            throw fail("two writes to an enabled bucket enumerated %d version(s)", listing.getVersionSummaries().size());
        }
        if (!new String(get(new GetObjectRequest(bucket, "versioned.bin", first.getVersionId()))).equals("first")) {
            throw fail("an explicit version read returned the wrong version's bytes");
        }
    }

    private void copyObject() throws IOException {
        put("source.bin", "copy me".getBytes());
        s3.copyObject(bucket, "source.bin", bucket, "target.bin");
        if (!new String(get("target.bin")).equals("copy me")) {
            throw fail("a server-side copy produced different bytes");
        }
    }

    private void deleteBatch() {
        List<KeyVersion> objects = new ArrayList<>();
        for (int index = 0; index < 10; index++) {
            String key = "batch/" + index + ".txt";
            put(key, "x".getBytes());
            objects.add(new KeyVersion(key));
        }
        s3.deleteObjects(new DeleteObjectsRequest(bucket).withKeys(objects).withQuiet(true));
        int remaining = s3.listObjectsV2(bucket).getKeyCount();
        if (remaining != 0) {
            throw fail("%d key(s) survived a batch delete", remaining);
        }
    }

    // The SDK's ordinary file body with every default left alone. Measured: over plaintext v1 frames
    // PutObject as STREAMING-AWS4-HMAC-SHA256-PAYLOAD with 128 KiB signed chunks and no trailer;
    // whether that arrived is the probe's call.
    private void streamingChunkedUpload() throws IOException {
        byte[] payload = random(9437184);
        Path file = work.resolve("streaming.bin");
        Files.write(file, payload);
        s3.putObject(bucket, "streaming.bin", file.toFile());
        byte[] read = get("streaming.bin");
        if (!Arrays.equals(read, payload)) {
            throw fail("read back %d bytes that differ from the %d written", read.length, payload.length);
        }
    }
}
