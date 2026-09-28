// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// aws-sdk-go (v2) scenario driver.
//
// Responsible for: turning one abstract scenario into aws-sdk-go-v2 calls and printing one result
// object on stdout. NOT responsible for: judging wire facts; the system under test records those
// and ci/compat/report.py evaluates them. Upstream: ci/compat/run_matrix.sh via run.sh.
// Downstream: ci/compat/report.py.
//
// `driver --client-version` prints the aws-sdk-go-v2 S3 module version this binary was linked
// against, read from its own build information, which is what the runner compares with the pin.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const s3Module = "github.com/aws/aws-sdk-go-v2/service/s3"

type result struct {
	Scenario string         `json:"scenario"`
	Status   string         `json:"status"`
	Detail   string         `json:"detail"`
	Evidence map[string]any `json:"evidence"`
}

// outcome ends a scenario early; main prints it.
type outcome struct{ result }

func (o outcome) Error() string { return o.Detail }

func fail(format string, args ...any) error {
	return outcome{result{Status: "fail", Detail: fmt.Sprintf(format, args...)}}
}

var unsupported = map[string]string{
	"backup-restore": "aws-sdk-go-v2 is an SDK, not a backup tool; it has no repository format to restore",
	"sync-directory": "aws-sdk-go-v2 offers no directory mirroring primitive",
	// Measured: over the plaintext endpoint PutObject declares the whole-payload SHA-256 for a
	// seekable body and cannot send an unseekable one at all ("failed to compute payload hash");
	// over TLS it declares UNSIGNED-PAYLOAD. No option selects signed aws-chunked framing.
	"streaming-chunked-upload": "aws-sdk-go-v2 signs whole payloads over plaintext and has no signed aws-chunked mode",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: driver <scenario-id> | --client-version")
		os.Exit(64)
	}
	scenario := os.Args[1]
	if scenario == "--client-version" {
		fmt.Println(linkedVersion())
		return
	}
	if reason, ok := unsupported[scenario]; ok {
		print(result{Scenario: scenario, Status: "unsupported", Detail: reason})
		return
	}
	run, ok := scenarios[scenario]
	if !ok {
		fmt.Fprintf(os.Stderr, "driver: unknown scenario %s\n", scenario)
		os.Exit(64)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := newDriver()
	err := d.createBucket(ctx)
	if err == nil {
		err = run(ctx, d)
	}
	var early outcome
	switch {
	case err == nil:
		print(result{Scenario: scenario, Status: "pass"})
	case errors.As(err, &early):
		early.Scenario = scenario
		print(early.result)
	default:
		print(result{Scenario: scenario, Status: "fail", Detail: describe(err)})
	}
}

func print(r result) {
	if r.Evidence == nil {
		r.Evidence = map[string]any{}
	}
	encoded, _ := json.Marshal(r) // a struct of strings and a map of strings cannot fail to encode
	fmt.Println(string(encoded))
}

// describe names the server's answer when there was one, and the client's error otherwise.
func describe(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Sprintf("%s: %s", api.ErrorCode(), api.ErrorMessage())
	}
	return err.Error()
}

func linkedVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "<no build information>"
	}
	for _, dep := range info.Deps {
		if dep.Path == s3Module {
			if dep.Replace != nil {
				return dep.Replace.Version
			}
			return dep.Version
		}
	}
	return "<" + s3Module + " not linked>"
}

type driver struct {
	s3     *s3.Client
	bucket string
	work   string
}

func client(endpoint string, httpClient aws.HTTPClient) *s3.Client {
	cfg := aws.Config{
		Region:           os.Getenv("COMPAT_REGION"),
		Credentials:      credentials.NewStaticCredentialsProvider(os.Getenv("COMPAT_ACCESS_KEY"), os.Getenv("COMPAT_SECRET_KEY"), ""),
		RetryMaxAttempts: 1,
	}
	if httpClient != nil {
		cfg.HTTPClient = httpClient
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

func newDriver() *driver {
	return &driver{
		s3:     client(os.Getenv("COMPAT_ENDPOINT"), nil),
		bucket: os.Getenv("COMPAT_BUCKET"),
		work:   os.Getenv("COMPAT_WORKDIR"),
	}
}

// tlsClient trusts exactly the runner's throwaway authority and nothing else.
func tlsClient() (*s3.Client, error) {
	endpoint, bundle := os.Getenv("COMPAT_TLS_ENDPOINT"), os.Getenv("COMPAT_CA_BUNDLE")
	if endpoint == "" || bundle == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(bundle)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", bundle)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return client(endpoint, &http.Client{Transport: transport}), nil
}

func (d *driver) createBucket(ctx context.Context) error {
	_, err := d.s3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(d.bucket)})
	return err
}

func random(size int) []byte {
	payload := make([]byte, size)
	_, _ = rand.Read(payload) // crypto/rand.Read never returns an error on supported platforms
	return payload
}

func (d *driver) get(ctx context.Context, key string, rangeHeader *string, version *string) ([]byte, error) {
	out, err := d.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(d.bucket), Key: aws.String(key), Range: rangeHeader, VersionId: version})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (d *driver) put(ctx context.Context, key string, body []byte) (*s3.PutObjectOutput, error) {
	return d.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.bucket), Key: aws.String(key), Body: bytes.NewReader(body)})
}

var scenarios = map[string]func(context.Context, *driver) error{
	"bucket-lifecycle":       bucketLifecycle,
	"small-object-roundtrip": smallObjectRoundtrip,
	"large-multipart-upload": largeMultipartUpload,
	"list-pagination":        listPagination,
	"range-download":         rangeDownload,
	"presigned-get":          presignedGet,
	"presigned-put":          presignedPut,
	"versioned-object":       versionedObject,
	"copy-object":            copyObject,
	"delete-batch":           deleteBatch,
	"trailer-chunked-upload": trailerChunkedUpload,
}

func bucketLifecycle(ctx context.Context, d *driver) error {
	if _, err := d.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(d.bucket)}); err != nil {
		return err
	}
	if _, err := d.s3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(d.bucket)}); err != nil {
		return err
	}
	if _, err := d.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(d.bucket)}); err == nil {
		return fail("the bucket answered HeadBucket after it was deleted")
	}
	return nil
}

func smallObjectRoundtrip(ctx context.Context, d *driver) error {
	payload := random(4096)
	if _, err := d.put(ctx, "small.bin", payload); err != nil {
		return err
	}
	read, err := d.get(ctx, "small.bin", nil, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(read, payload) {
		return fail("read back %d bytes that differ from the %d written", len(read), len(payload))
	}
	head, err := d.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("small.bin")})
	if err != nil {
		return err
	}
	if aws.ToInt64(head.ContentLength) != int64(len(payload)) {
		return fail("HeadObject reported %d for a %d byte object", aws.ToInt64(head.ContentLength), len(payload))
	}
	return nil
}

func largeMultipartUpload(ctx context.Context, d *driver) error {
	payload := random(12 * 1024 * 1024)
	uploader := manager.NewUploader(d.s3, func(u *manager.Uploader) { u.PartSize = 5 * 1024 * 1024 })
	if _, err := uploader.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("multipart.bin"), Body: bytes.NewReader(payload)}); err != nil {
		return err
	}
	read, err := d.get(ctx, "multipart.bin", nil, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(read, payload) {
		return fail("read back %d bytes that differ from the %d written", len(read), len(payload))
	}
	head, err := d.s3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("multipart.bin")})
	if err != nil {
		return err
	}
	if !strings.Contains(aws.ToString(head.ETag), "-") {
		return fail("a multipart object reported the single-part entity tag %s", aws.ToString(head.ETag))
	}
	return nil
}

func listPagination(ctx context.Context, d *driver) error {
	var keys []string
	for index := 0; index < 25; index++ {
		key := fmt.Sprintf("page/%04d.txt", index)
		keys = append(keys, key)
		if _, err := d.put(ctx, key, []byte(key)); err != nil {
			return err
		}
	}
	paginator := s3.NewListObjectsV2Paginator(d.s3, &s3.ListObjectsV2Input{Bucket: aws.String(d.bucket), Prefix: aws.String("page/"), MaxKeys: aws.Int32(7)})
	var seen []string
	pages := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		pages++
		for _, entry := range page.Contents {
			seen = append(seen, aws.ToString(entry.Key))
		}
		if pages > 20 {
			return fail("the listing did not terminate within 20 pages")
		}
	}
	sort.Strings(seen)
	if strings.Join(seen, ",") != strings.Join(keys, ",") {
		return fail("listed %d keys over %d page(s), expected %d", len(seen), pages, len(keys))
	}
	if pages < 2 {
		return fail("a %d key listing at page size 7 returned %d page(s)", len(keys), pages)
	}
	return nil
}

func rangeDownload(ctx context.Context, d *driver) error {
	payload := random(1024 * 1024)
	if _, err := d.put(ctx, "ranged.bin", payload); err != nil {
		return err
	}
	read, err := d.get(ctx, "ranged.bin", aws.String("bytes=1000-5000"), nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(read, payload[1000:5001]) {
		return fail("bytes=1000-5000 returned %d bytes that differ from the same slice of the source", len(read))
	}
	return nil
}

// redeem sends a presigned request with a plain HTTP client: generation is the SDK's half and
// verification the server's, so the SDK must not be the one to send it.
func redeem(method, url string, headers http.Header, body []byte) (int, []byte, error) {
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for name, values := range headers {
		if strings.EqualFold(name, "host") {
			continue
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if body != nil {
		request.ContentLength = int64(len(body))
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	read, err := io.ReadAll(response.Body)
	return response.StatusCode, read, err
}

func presignedGet(ctx context.Context, d *driver) error {
	payload := random(2048)
	if _, err := d.put(ctx, "presigned.bin", payload); err != nil {
		return err
	}
	presigned, err := s3.NewPresignClient(d.s3).PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("presigned.bin")}, s3.WithPresignExpires(5*time.Minute))
	if err != nil {
		return err
	}
	status, body, err := redeem(presigned.Method, presigned.URL, presigned.SignedHeader, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fail("a presigned GET was answered %d", status)
	}
	if !bytes.Equal(body, payload) {
		return fail("a presigned GET returned %d bytes, expected %d", len(body), len(payload))
	}
	return nil
}

func presignedPut(ctx context.Context, d *driver) error {
	payload := random(2048)
	presigned, err := s3.NewPresignClient(d.s3).PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("presigned-put.bin")}, s3.WithPresignExpires(5*time.Minute))
	if err != nil {
		return err
	}
	status, _, err := redeem(presigned.Method, presigned.URL, presigned.SignedHeader, payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fail("a presigned PUT was answered %d", status)
	}
	read, err := d.get(ctx, "presigned-put.bin", nil, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(read, payload) {
		return fail("a presigned PUT stored bytes that differ from the ones sent")
	}
	return nil
}

func versionedObject(ctx context.Context, d *driver) error {
	if _, err := d.s3.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(d.bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		return err
	}
	status, err := d.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(d.bucket)})
	if err != nil {
		return err
	}
	if status.Status != types.BucketVersioningStatusEnabled {
		return fail("versioning reported %q after it was enabled", status.Status)
	}
	first, err := d.put(ctx, "versioned.bin", []byte("first"))
	if err != nil {
		return err
	}
	if _, err := d.put(ctx, "versioned.bin", []byte("second")); err != nil {
		return err
	}
	listing, err := d.s3.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(d.bucket), Prefix: aws.String("versioned.bin")})
	if err != nil {
		return err
	}
	if len(listing.Versions) < 2 {
		return fail("two writes to an enabled bucket enumerated %d version(s)", len(listing.Versions))
	}
	oldest, err := d.get(ctx, "versioned.bin", nil, first.VersionId)
	if err != nil {
		return err
	}
	if string(oldest) != "first" {
		return fail("an explicit version read returned the wrong version's bytes")
	}
	return nil
}

func copyObject(ctx context.Context, d *driver) error {
	if _, err := d.put(ctx, "source.bin", []byte("copy me")); err != nil {
		return err
	}
	if _, err := d.s3.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("target.bin"), CopySource: aws.String(d.bucket + "/source.bin")}); err != nil {
		return err
	}
	read, err := d.get(ctx, "target.bin", nil, nil)
	if err != nil {
		return err
	}
	if string(read) != "copy me" {
		return fail("a server-side copy produced different bytes")
	}
	return nil
}

func deleteBatch(ctx context.Context, d *driver) error {
	var objects []types.ObjectIdentifier
	for index := 0; index < 10; index++ {
		key := fmt.Sprintf("batch/%d.txt", index)
		if _, err := d.put(ctx, key, []byte("x")); err != nil {
			return err
		}
		objects = append(objects, types.ObjectIdentifier{Key: aws.String(key)})
	}
	if _, err := d.s3.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(d.bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}}); err != nil {
		return err
	}
	listing, err := d.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(d.bucket)})
	if err != nil {
		return err
	}
	if aws.ToInt32(listing.KeyCount) != 0 {
		return fail("%d key(s) survived a batch delete", aws.ToInt32(listing.KeyCount))
	}
	return nil
}

// trailerChunkedUpload sends an unseekable body over TLS and names CRC32 as the checksum.
// Measured: that is the shape for which aws-sdk-go-v2 carries the checksum in an x-amz-trailer
// behind aws-chunked framing (without the explicit algorithm it declares UNSIGNED-PAYLOAD and
// sends no checksum at all). Nothing here writes the trailer; whether one arrived is the probe's
// call, not this driver's.
func trailerChunkedUpload(ctx context.Context, d *driver) error {
	secure, err := tlsClient()
	if err != nil {
		return err
	}
	if secure == nil {
		return outcome{result{Status: "unsupported", Detail: "the runner offered no TLS endpoint, and aws-sdk-go-v2 sends a trailer only on the unsigned-payload path it takes over TLS"}}
	}
	payload := random(1024 * 1024)
	unseekable := struct{ io.Reader }{bytes.NewReader(payload)}
	if _, err := secure.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.bucket), Key: aws.String("trailer.bin"), Body: unseekable, ContentLength: aws.Int64(int64(len(payload))), ChecksumAlgorithm: types.ChecksumAlgorithmCrc32}); err != nil {
		return err
	}
	read, err := d.get(ctx, "trailer.bin", nil, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(read, payload) {
		return fail("read back %d bytes that differ from the %d written", len(read), len(payload))
	}
	return nil
}
