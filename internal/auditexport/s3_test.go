package auditexport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type fakeSTS struct{ account, arn string }

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account), Arn: aws.String(f.arn)}, nil
}

type fakeS3 struct {
	object       *s3.HeadObjectOutput
	putCalls     int
	lostResponse bool
}

func (f *fakeS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled}, nil
}

func (f *fakeS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	years := int32(10)
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
		ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
		Rule: &s3types.ObjectLockRule{DefaultRetention: &s3types.DefaultRetention{
			Mode: s3types.ObjectLockRetentionModeCompliance, Years: &years,
		}},
	}}, nil
}

func (f *fakeS3) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if f.object == nil {
		return nil, &smithy.GenericAPIError{Code: "NotFound", Message: "not found"}
	}
	return f.object, nil
}

func (f *fakeS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.putCalls++
	if input.IfNoneMatch == nil || *input.IfNoneMatch != "*" ||
		input.ObjectLockMode != s3types.ObjectLockModeCompliance ||
		input.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 ||
		input.ChecksumSHA256 == nil || input.ObjectLockRetainUntilDate == nil {
		return nil, errors.New("unsafe put controls")
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	if *input.ChecksumSHA256 != base64.StdEncoding.EncodeToString(digest[:]) {
		return nil, errors.New("checksum does not cover body")
	}
	f.object = &s3.HeadObjectOutput{
		ChecksumSHA256:            input.ChecksumSHA256,
		ContentLength:             aws.Int64(int64(len(body))),
		Metadata:                  input.Metadata,
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: input.ObjectLockRetainUntilDate,
		VersionId:                 aws.String("version-7"), ETag: aws.String("etag-7"),
	}
	if f.lostResponse {
		return nil, errors.New("connection reset after provider commit")
	}
	return &s3.PutObjectOutput{}, nil
}

func validS3Config() S3Config {
	return S3Config{
		ID: "sink-a", Endpoint: "https://worm-a.example", Bucket: "audit-a",
		Region: "region-a", RoleARN: "arn:provider:iam::account-a:role/audit",
		WebIdentityTokenFile: "/var/run/identity/token", ExpectedAccountID: "account-a",
	}
}

func validArtifact() Artifact {
	body := []byte("canonical manifest\n")
	return Artifact{
		BookID: "book-a", LastSequence: 9, Format: ManifestFormat,
		ObjectKey: "audit/v1/object.json", Bytes: body, SHA256: sha256.Sum256(body),
		RetainUntil: time.Date(2036, 8, 16, 0, 0, 0, 0, time.UTC),
	}
}

func TestS3SinkRecoversLostPutResponseByHead(t *testing.T) {
	backend := &fakeS3{lostResponse: true}
	sink, err := newS3SinkForTest(validS3Config(), backend, fakeSTS{account: "account-a", arn: "arn:provider:sts::account-a:assumed-role/audit/session"})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := sink.Ensure(context.Background(), validArtifact())
	if err != nil {
		t.Fatal(err)
	}
	if backend.putCalls != 1 || evidence.VersionID != "version-7" || evidence.ProviderIdentity == "" {
		t.Fatalf("lost response did not resolve to immutable evidence: calls=%d evidence=%+v", backend.putCalls, evidence)
	}
	if _, err := sink.Ensure(context.Background(), validArtifact()); err != nil {
		t.Fatal(err)
	}
	if backend.putCalls != 1 {
		t.Fatal("existing same-content object was overwritten")
	}
}

func TestS3SinkTreatsExistingDifferentChecksumAsP0(t *testing.T) {
	artifact := validArtifact()
	other := sha256.Sum256([]byte("different"))
	backend := &fakeS3{object: &s3.HeadObjectOutput{
		ChecksumSHA256:            aws.String(base64.StdEncoding.EncodeToString(other[:])),
		ContentLength:             aws.Int64(int64(len(artifact.Bytes))),
		Metadata:                  map[string]string{"payment-platform-sha256": "wrong"},
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(artifact.RetainUntil.Add(time.Hour)),
		VersionId:                 aws.String("version-old"), ETag: aws.String("etag-old"),
	}}
	sink, err := newS3SinkForTest(validS3Config(), backend, fakeSTS{account: "account-a", arn: "arn:a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sink.Ensure(context.Background(), artifact)
	if !errors.Is(err, ErrWORMConflict) {
		t.Fatalf("expected P0 conflict, got %v", err)
	}
	if backend.putCalls != 0 {
		t.Fatal("conflicting immutable object was overwritten")
	}
}

func TestS3SinkRejectsWeakBucketControlsAndHTTP(t *testing.T) {
	config := validS3Config()
	config.Endpoint = "http://worm-a.example"
	if _, err := newS3SinkForTest(config, &fakeS3{}, fakeSTS{}); err == nil {
		t.Fatal("plaintext object endpoint accepted")
	}
	backend := &fakeS3{}
	sink, err := newS3SinkForTest(validS3Config(), backend, fakeSTS{account: "wrong", arn: "arn:wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Probe(context.Background()); err == nil {
		t.Fatal("wrong workload identity accepted")
	}
}
