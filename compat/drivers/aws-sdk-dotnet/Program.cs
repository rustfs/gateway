// aws-sdk-dotnet scenario driver.
//
// Responsible for: turning one abstract scenario into AWSSDK.S3 calls and printing one result
// object on stdout. NOT responsible for: judging wire facts; the system under test records those
// and ci/compat/report.py evaluates them. Upstream: ci/compat/run_matrix.sh via run.sh.
// Downstream: ci/compat/report.py.
//
// `driver --client-version` prints the version of the AWSSDK.S3 assembly this program loaded, read
// from that assembly's own metadata, which is what the runner compares with the pin.

using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;

namespace CompatDriver;

/// <summary>Ends a scenario early with a status of its own; Main prints it.</summary>
sealed class Outcome(string status, string detail) : Exception(detail)
{
    public string Status { get; } = status;

    public static Outcome Fail(string detail) => new("fail", detail);
}

static class Program
{
    static readonly Dictionary<string, string> Unsupported = new()
    {
        ["backup-restore"] = "aws-sdk-dotnet is an SDK, not a backup tool; it has no repository format to restore",
        ["sync-directory"] = "aws-sdk-dotnet offers no directory mirroring primitive",
    };

    static readonly Dictionary<string, Func<Driver, Task>> Scenarios = new()
    {
        ["bucket-lifecycle"] = BucketLifecycle,
        ["small-object-roundtrip"] = SmallObjectRoundtrip,
        ["large-multipart-upload"] = LargeMultipartUpload,
        ["list-pagination"] = ListPagination,
        ["range-download"] = RangeDownload,
        ["presigned-get"] = PresignedGet,
        ["presigned-put"] = PresignedPut,
        ["versioned-object"] = VersionedObject,
        ["copy-object"] = CopyObject,
        ["delete-batch"] = DeleteBatch,
        ["streaming-chunked-upload"] = StreamingChunkedUpload,
        ["trailer-chunked-upload"] = TrailerChunkedUpload,
    };

    static async Task<int> Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("usage: driver <scenario-id> | --client-version");
            return 64;
        }
        var scenario = args[0];
        if (scenario == "--client-version")
        {
            Console.WriteLine(LinkedVersion());
            return 0;
        }
        if (Unsupported.TryGetValue(scenario, out var reason))
        {
            Print(scenario, "unsupported", reason);
            return 0;
        }
        if (!Scenarios.TryGetValue(scenario, out var run))
        {
            Console.Error.WriteLine($"driver: unknown scenario {scenario}");
            return 64;
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        try
        {
            var driver = new Driver(timeout.Token);
            await driver.CreateBucket();
            await run(driver);
            Print(scenario, "pass", "");
        }
        catch (Outcome early)
        {
            Print(scenario, early.Status, early.Message);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            Print(scenario, "fail", Describe(error));
        }
        return 0;
    }

    static void Print(string scenario, string status, string detail)
    {
        var line = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["scenario"] = scenario,
            ["status"] = status,
            ["detail"] = detail,
            ["evidence"] = new Dictionary<string, object>(),
        });
        Console.WriteLine(line);
    }

    /// <summary>Names the server's answer when there was one, and the client's error otherwise.</summary>
    static string Describe(Exception error)
    {
        if (error is AmazonServiceException service && !string.IsNullOrEmpty(service.ErrorCode))
        {
            return $"{service.ErrorCode}: {service.Message}";
        }
        if (error is OperationCanceledException)
        {
            return "the scenario did not finish within 4 minutes";
        }
        return $"{error.GetType().Name}: {error.Message}";
    }

    /// <summary>
    /// The NuGet package version is the assembly's file version (its AssemblyVersion is only the
    /// major version, 4.0.0.0); the informational version repeats it, sometimes with a suffix.
    /// </summary>
    static string LinkedVersion()
    {
        var assembly = typeof(AmazonS3Client).Assembly;
        var file = assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
        return string.IsNullOrEmpty(file) ? $"<{assembly.GetName().Name} has no file version>" : file;
    }

    static async Task BucketLifecycle(Driver d)
    {
        await d.S3.HeadBucketAsync(new HeadBucketRequest { BucketName = d.Bucket }, d.Token);
        await d.S3.DeleteBucketAsync(new DeleteBucketRequest { BucketName = d.Bucket }, d.Token);
        try
        {
            await d.S3.HeadBucketAsync(new HeadBucketRequest { BucketName = d.Bucket }, d.Token);
        }
        catch (AmazonS3Exception)
        {
            return;
        }
        throw Outcome.Fail("the bucket answered HeadBucket after it was deleted");
    }

    static async Task SmallObjectRoundtrip(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(4096);
        await d.Put("small.bin", payload);
        var read = await d.Get("small.bin");
        if (!read.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail($"read back {read.Length} bytes that differ from the {payload.Length} written");
        }
        var head = await d.S3.GetObjectMetadataAsync(new GetObjectMetadataRequest { BucketName = d.Bucket, Key = "small.bin" }, d.Token);
        if (head.ContentLength != payload.Length)
        {
            throw Outcome.Fail($"HeadObject reported {head.ContentLength} for a {payload.Length} byte object");
        }
    }

    const long PartSize = 5 * 1024 * 1024;

    static async Task LargeMultipartUpload(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(12 * 1024 * 1024);
        // TransferUtility switches to multipart only at 16 MiB by default; lowering its threshold to
        // the part size makes it split the way every other SDK's uploader here does.
        var transfer = new TransferUtility(d.S3, new TransferUtilityConfig { MinSizeBeforePartUpload = PartSize });
        await transfer.UploadAsync(new TransferUtilityUploadRequest
        {
            BucketName = d.Bucket,
            Key = "multipart.bin",
            InputStream = new MemoryStream(payload),
            PartSize = PartSize,
        }, d.Token);
        var read = await d.Get("multipart.bin");
        if (!read.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail($"read back {read.Length} bytes that differ from the {payload.Length} written");
        }
        var head = await d.S3.GetObjectMetadataAsync(new GetObjectMetadataRequest { BucketName = d.Bucket, Key = "multipart.bin" }, d.Token);
        if (head.ETag is null || !head.ETag.Contains('-'))
        {
            throw Outcome.Fail($"a multipart object reported the single-part entity tag {head.ETag}");
        }
    }

    static async Task ListPagination(Driver d)
    {
        var keys = new List<string>();
        for (var index = 0; index < 25; index++)
        {
            var key = $"page/{index:D4}.txt";
            keys.Add(key);
            await d.Put(key, Encoding.UTF8.GetBytes(key));
        }
        var paginator = d.S3.Paginators.ListObjectsV2(new ListObjectsV2Request { BucketName = d.Bucket, Prefix = "page/", MaxKeys = 7 });
        var seen = new List<string>();
        var pages = 0;
        await foreach (var page in paginator.Responses.WithCancellation(d.Token))
        {
            pages++;
            seen.AddRange((page.S3Objects ?? []).Select(entry => entry.Key));
            if (pages > 20)
            {
                throw Outcome.Fail("the listing did not terminate within 20 pages");
            }
        }
        seen.Sort(StringComparer.Ordinal);
        if (!seen.SequenceEqual(keys))
        {
            throw Outcome.Fail($"listed {seen.Count} keys over {pages} page(s), expected {keys.Count}");
        }
        if (pages < 2)
        {
            throw Outcome.Fail($"a {keys.Count} key listing at page size 7 returned {pages} page(s)");
        }
    }

    static async Task RangeDownload(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        await d.Put("ranged.bin", payload);
        var read = await d.Get("ranged.bin", range: new ByteRange(1000, 5000));
        if (!read.AsSpan().SequenceEqual(payload.AsSpan(1000, 4001)))
        {
            throw Outcome.Fail($"bytes=1000-5000 returned {read.Length} bytes that differ from the same slice of the source");
        }
    }

    /// <summary>
    /// Sends a presigned request with a plain HTTP client: generation is the SDK's half and
    /// verification the server's, so the SDK must not be the one to send it.
    /// </summary>
    static async Task<(int Status, byte[] Body)> Redeem(HttpMethod method, string url, byte[]? body, CancellationToken token)
    {
        using var http = new HttpClient();
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
        }
        using var response = await http.SendAsync(request, token);
        return ((int)response.StatusCode, await response.Content.ReadAsByteArrayAsync(token));
    }

    static async Task PresignedGet(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(2048);
        await d.Put("presigned.bin", payload);
        var url = await d.S3.GetPreSignedURLAsync(d.Presign("presigned.bin", HttpVerb.GET));
        var (status, body) = await Redeem(HttpMethod.Get, url, null, d.Token);
        if (status != 200)
        {
            throw Outcome.Fail($"a presigned GET was answered {status}");
        }
        if (!body.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail($"a presigned GET returned {body.Length} bytes, expected {payload.Length}");
        }
    }

    static async Task PresignedPut(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(2048);
        var url = await d.S3.GetPreSignedURLAsync(d.Presign("presigned-put.bin", HttpVerb.PUT));
        var (status, _) = await Redeem(HttpMethod.Put, url, payload, d.Token);
        if (status != 200 && status != 201)
        {
            throw Outcome.Fail($"a presigned PUT was answered {status}");
        }
        var read = await d.Get("presigned-put.bin");
        if (!read.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail("a presigned PUT stored bytes that differ from the ones sent");
        }
    }

    static async Task VersionedObject(Driver d)
    {
        await d.S3.PutBucketVersioningAsync(new PutBucketVersioningRequest
        {
            BucketName = d.Bucket,
            VersioningConfig = new S3BucketVersioningConfig { Status = VersionStatus.Enabled },
        }, d.Token);
        var status = await d.S3.GetBucketVersioningAsync(new GetBucketVersioningRequest { BucketName = d.Bucket }, d.Token);
        if (status.VersioningConfig?.Status != VersionStatus.Enabled)
        {
            throw Outcome.Fail($"versioning reported \"{status.VersioningConfig?.Status}\" after it was enabled");
        }
        var first = await d.Put("versioned.bin", Encoding.UTF8.GetBytes("first"));
        await d.Put("versioned.bin", Encoding.UTF8.GetBytes("second"));
        var listing = await d.S3.ListVersionsAsync(new ListVersionsRequest { BucketName = d.Bucket, Prefix = "versioned.bin" }, d.Token);
        var versions = listing.Versions?.Count ?? 0;
        if (versions < 2)
        {
            throw Outcome.Fail($"two writes to an enabled bucket enumerated {versions} version(s)");
        }
        var oldest = await d.Get("versioned.bin", version: first.VersionId);
        if (Encoding.UTF8.GetString(oldest) != "first")
        {
            throw Outcome.Fail("an explicit version read returned the wrong version's bytes");
        }
    }

    static async Task CopyObject(Driver d)
    {
        await d.Put("source.bin", Encoding.UTF8.GetBytes("copy me"));
        await d.S3.CopyObjectAsync(new CopyObjectRequest
        {
            SourceBucket = d.Bucket,
            SourceKey = "source.bin",
            DestinationBucket = d.Bucket,
            DestinationKey = "target.bin",
        }, d.Token);
        var read = await d.Get("target.bin");
        if (Encoding.UTF8.GetString(read) != "copy me")
        {
            throw Outcome.Fail("a server-side copy produced different bytes");
        }
    }

    static async Task DeleteBatch(Driver d)
    {
        var objects = new List<KeyVersion>();
        for (var index = 0; index < 10; index++)
        {
            var key = $"batch/{index}.txt";
            await d.Put(key, Encoding.UTF8.GetBytes("x"));
            objects.Add(new KeyVersion { Key = key });
        }
        await d.S3.DeleteObjectsAsync(new DeleteObjectsRequest { BucketName = d.Bucket, Objects = objects, Quiet = true }, d.Token);
        var listing = await d.S3.ListObjectsV2Async(new ListObjectsV2Request { BucketName = d.Bucket }, d.Token);
        var remaining = listing.KeyCount ?? 0;
        if (remaining != 0)
        {
            throw Outcome.Fail($"{remaining} key(s) survived a batch delete");
        }
    }

    /// <summary>
    /// Uploads a 9 MiB file from disk with a plain PutObject over the plaintext endpoint.
    /// Measured: with its defaults the SDK signs that as STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER,
    /// aws-chunked in 81920-byte signed chunks followed by a signed x-amz-checksum-crc32 trailer.
    /// Nothing here selects that framing; whether it arrived is the probe's call, not this driver's.
    /// </summary>
    static async Task StreamingChunkedUpload(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(9 * 1024 * 1024);
        var path = Path.Combine(d.Work, "streaming.bin");
        await File.WriteAllBytesAsync(path, payload, d.Token);
        await d.S3.PutObjectAsync(new PutObjectRequest { BucketName = d.Bucket, Key = "streaming.bin", FilePath = path }, d.Token);
        var read = await d.Get("streaming.bin");
        if (!read.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail($"read back {read.Length} bytes that differ from the {payload.Length} written");
        }
    }

    /// <summary>
    /// Uploads 1 MiB from a stream of known length with a plain PutObject over the plaintext
    /// endpoint. Measured: the SDK's default checksum policy (CRC32 when supported) carries the
    /// checksum in a declared, signed x-amz-trailer behind Content-Encoding: aws-chunked, so no TLS
    /// endpoint and no explicit checksum setting is needed to reach the trailer path.
    /// </summary>
    static async Task TrailerChunkedUpload(Driver d)
    {
        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        await d.S3.PutObjectAsync(new PutObjectRequest { BucketName = d.Bucket, Key = "trailer.bin", InputStream = new MemoryStream(payload) }, d.Token);
        var read = await d.Get("trailer.bin");
        if (!read.AsSpan().SequenceEqual(payload))
        {
            throw Outcome.Fail($"read back {read.Length} bytes that differ from the {payload.Length} written");
        }
    }
}

/// <summary>One scenario's client, bucket and deadline.</summary>
sealed class Driver
{
    public AmazonS3Client S3 { get; }
    public string Bucket { get; }
    public string Work { get; }
    public CancellationToken Token { get; }
    readonly Protocol presignProtocol;

    public Driver(CancellationToken token)
    {
        var endpoint = Environment.GetEnvironmentVariable("COMPAT_ENDPOINT")!;
        var config = new AmazonS3Config
        {
            ServiceURL = endpoint,
            ForcePathStyle = true,
            AuthenticationRegion = Environment.GetEnvironmentVariable("COMPAT_REGION"),
            MaxErrorRetry = 0,
        };
        var credentials = new BasicAWSCredentials(
            Environment.GetEnvironmentVariable("COMPAT_ACCESS_KEY"),
            Environment.GetEnvironmentVariable("COMPAT_SECRET_KEY"));
        S3 = new AmazonS3Client(credentials, config);
        Bucket = Environment.GetEnvironmentVariable("COMPAT_BUCKET")!;
        Work = Environment.GetEnvironmentVariable("COMPAT_WORKDIR")!;
        Token = token;
        // A presigned URL's scheme comes from the request, not the client, and defaults to https.
        presignProtocol = endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? Protocol.HTTPS : Protocol.HTTP;
    }

    public Task CreateBucket() => S3.PutBucketAsync(new PutBucketRequest { BucketName = Bucket }, Token);

    public Task<PutObjectResponse> Put(string key, byte[] body) =>
        S3.PutObjectAsync(new PutObjectRequest { BucketName = Bucket, Key = key, InputStream = new MemoryStream(body) }, Token);

    public async Task<byte[]> Get(string key, ByteRange? range = null, string? version = null)
    {
        using var response = await S3.GetObjectAsync(new GetObjectRequest { BucketName = Bucket, Key = key, ByteRange = range, VersionId = version }, Token);
        using var buffer = new MemoryStream();
        await response.ResponseStream.CopyToAsync(buffer, Token);
        return buffer.ToArray();
    }

    public GetPreSignedUrlRequest Presign(string key, HttpVerb verb) => new()
    {
        BucketName = Bucket,
        Key = key,
        Verb = verb,
        Protocol = presignProtocol,
        Expires = DateTime.UtcNow.AddMinutes(5),
    };
}
