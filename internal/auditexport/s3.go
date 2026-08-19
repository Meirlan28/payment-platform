package auditexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const objectLockSafetyMargin = 24 * time.Hour

var sinkSessionName = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,40}$`)

type S3Config struct {
	ID                   string
	Endpoint             string
	Bucket               string
	Region               string
	RoleARN              string
	WebIdentityTokenFile string
	STSEndpoint          string
	ExpectedAccountID    string
	UsePathStyle         bool
	HTTPClient           *http.Client
}

type s3API interface {
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type stsAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type S3Sink struct {
	config   S3Config
	endpoint *url.URL
	s3       s3API
	identity stsAPI

	mu               sync.RWMutex
	providerIdentity string
	lastProbe        time.Time
}

func NewS3Sink(ctx context.Context, config S3Config) (*S3Sink, error) {
	endpoint, err := validateS3Config(config)
	if err != nil {
		return nil, err
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(config.Region),
		// The STS AssumeRoleWithWebIdentity operation is unsigned. No ambient
		// node/instance credential is permitted as a silent fallback.
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	}
	if config.HTTPClient != nil {
		loadOptions = append(loadOptions, awsconfig.WithHTTPClient(config.HTTPClient))
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("audit export: load AWS transport config: %w", err)
	}
	stsOptions := func(options *sts.Options) {}
	if config.STSEndpoint != "" {
		stsOptions = func(options *sts.Options) { options.BaseEndpoint = aws.String(config.STSEndpoint) }
	}
	unsignedSTS := sts.NewFromConfig(base, stsOptions)
	provider := stscreds.NewWebIdentityRoleProvider(
		unsignedSTS, config.RoleARN,
		stscreds.IdentityTokenFile(config.WebIdentityTokenFile),
		func(options *stscreds.WebIdentityRoleOptions) {
			options.RoleSessionName = "audit-checkpointer-" + config.ID
			options.Duration = 15 * time.Minute
		},
	)
	base.Credentials = aws.NewCredentialsCache(provider)
	identity := sts.NewFromConfig(base, stsOptions)
	s3Client := s3.NewFromConfig(base, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = config.UsePathStyle
	})
	return &S3Sink{config: config, endpoint: endpoint, s3: s3Client, identity: identity}, nil
}

func newS3SinkForTest(config S3Config, client s3API, identity stsAPI) (*S3Sink, error) {
	endpoint, err := validateS3Config(config)
	if err != nil {
		return nil, err
	}
	if client == nil || identity == nil {
		return nil, errors.New("audit export: S3 and STS clients are required")
	}
	return &S3Sink{config: config, endpoint: endpoint, s3: client, identity: identity}, nil
}

func validateS3Config(config S3Config) (*url.URL, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("audit export: S3 endpoint must be an HTTPS authority/base path")
	}
	if !sinkSessionName.MatchString(config.ID) || config.Bucket == "" || config.Region == "" ||
		config.RoleARN == "" || config.WebIdentityTokenFile == "" ||
		config.ExpectedAccountID == "" {
		return nil, errors.New("audit export: incomplete S3 workload-identity configuration")
	}
	if config.STSEndpoint != "" {
		stsEndpoint, parseErr := url.Parse(config.STSEndpoint)
		if parseErr != nil || stsEndpoint.Scheme != "https" || stsEndpoint.Host == "" {
			return nil, errors.New("audit export: STS endpoint must use HTTPS")
		}
	}
	return endpoint, nil
}

func (s *S3Sink) Descriptor() SinkDescriptor {
	return SinkDescriptor{
		ID: s.config.ID, EndpointAuthority: s.endpoint.Host,
		Bucket: s.config.Bucket, IdentityDomain: s.config.ExpectedAccountID,
	}
}

func (s *S3Sink) Probe(ctx context.Context) error {
	identity, err := s.identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("audit export: %s workload identity: %w", s.config.ID, err)
	}
	if identity.Account == nil || *identity.Account != s.config.ExpectedAccountID ||
		identity.Arn == nil || *identity.Arn == "" {
		return fmt.Errorf("audit export: %s workload identity does not match expected account", s.config.ID)
	}
	versioning, err := s.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(s.config.Bucket),
	})
	if err != nil {
		return fmt.Errorf("audit export: %s versioning evidence: %w", s.config.ID, err)
	}
	if versioning.Status != s3types.BucketVersioningStatusEnabled {
		return fmt.Errorf("audit export: %s bucket versioning is not enabled", s.config.ID)
	}
	lock, err := s.s3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(s.config.Bucket),
	})
	if err != nil {
		return fmt.Errorf("audit export: %s Object Lock evidence: %w", s.config.ID, err)
	}
	if !validDefaultComplianceRetention(lock.ObjectLockConfiguration) {
		return fmt.Errorf("audit export: %s requires Object Lock COMPLIANCE default retention of at least ten years", s.config.ID)
	}
	s.mu.Lock()
	s.providerIdentity = *identity.Arn
	s.lastProbe = time.Now()
	s.mu.Unlock()
	return nil
}

func validDefaultComplianceRetention(configuration *s3types.ObjectLockConfiguration) bool {
	if configuration == nil || configuration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled ||
		configuration.Rule == nil || configuration.Rule.DefaultRetention == nil ||
		configuration.Rule.DefaultRetention.Mode != s3types.ObjectLockRetentionModeCompliance {
		return false
	}
	retention := configuration.Rule.DefaultRetention
	if retention.Years != nil && *retention.Years >= RetentionYears {
		return true
	}
	// 3653 includes all leap-year arrangements in any closed ten-year span.
	return retention.Days != nil && *retention.Days >= 3653
}

func (s *S3Sink) Ensure(ctx context.Context, artifact Artifact) (ObjectEvidence, error) {
	if sha256.Sum256(artifact.Bytes) != artifact.SHA256 || artifact.ObjectKey == "" ||
		artifact.RetainUntil.IsZero() {
		return ObjectEvidence{}, errors.New("audit export: invalid object artifact")
	}
	if err := s.requireRecentProbe(ctx); err != nil {
		return ObjectEvidence{}, err
	}
	if evidence, found, err := s.headAndVerify(ctx, artifact); found || err != nil {
		return evidence, err
	}
	checksum := base64.StdEncoding.EncodeToString(artifact.SHA256[:])
	length := int64(len(artifact.Bytes))
	requestedRetention := artifact.RetainUntil.Add(objectLockSafetyMargin)
	_, putErr := s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(s.config.Bucket),
		Key:                       aws.String(artifact.ObjectKey),
		Body:                      bytes.NewReader(artifact.Bytes),
		ContentLength:             aws.Int64(length),
		ContentType:               aws.String("application/json"),
		ChecksumAlgorithm:         s3types.ChecksumAlgorithmSha256,
		ChecksumSHA256:            aws.String(checksum),
		IfNoneMatch:               aws.String("*"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(requestedRetention),
		Metadata: map[string]string{
			"payment-platform-format": artifact.Format,
			"payment-platform-sha256": fmt.Sprintf("%x", artifact.SHA256),
		},
	})
	// Both an ambiguous/lost response and a precondition race are resolved by
	// HEAD plus immutable checksum/retention verification. We never overwrite.
	evidence, found, headErr := s.headAndVerify(ctx, artifact)
	if found || headErr != nil {
		return evidence, headErr
	}
	if putErr != nil {
		return ObjectEvidence{}, fmt.Errorf("audit export: %s put object: %w", s.config.ID, putErr)
	}
	return ObjectEvidence{}, errors.New("audit export: object missing after successful put")
}

// Verify never creates or replaces an object. It is the external half of
// receipt validation: a raw database INSERT cannot make a worker accept WORM
// durability unless HEAD independently proves the immutable object.
func (s *S3Sink) Verify(ctx context.Context, artifact Artifact) (ObjectEvidence, error) {
	if sha256.Sum256(artifact.Bytes) != artifact.SHA256 || artifact.ObjectKey == "" ||
		artifact.RetainUntil.IsZero() {
		return ObjectEvidence{}, errors.New("audit export: invalid object artifact")
	}
	if err := s.requireRecentProbe(ctx); err != nil {
		return ObjectEvidence{}, err
	}
	evidence, found, err := s.headAndVerify(ctx, artifact)
	if err != nil {
		return ObjectEvidence{}, err
	}
	if !found {
		return ObjectEvidence{}, &ConflictError{
			SinkID: s.config.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256,
			Reason:         "durable receipt points to a missing immutable object",
		}
	}
	return evidence, nil
}

func (s *S3Sink) requireRecentProbe(ctx context.Context) error {
	s.mu.RLock()
	lastProbe := s.lastProbe
	identity := s.providerIdentity
	s.mu.RUnlock()
	// time.Since uses Go's monotonic component, so a 15-minute wall-clock jump
	// cannot indefinitely extend this control-plane evidence window.
	if identity != "" && !lastProbe.IsZero() && time.Since(lastProbe) >= 0 &&
		time.Since(lastProbe) <= 30*time.Second {
		return nil
	}
	return s.Probe(ctx)
}

func (s *S3Sink) headAndVerify(ctx context.Context, artifact Artifact) (ObjectEvidence, bool, error) {
	head, err := s.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.config.Bucket), Key: aws.String(artifact.ObjectKey),
		ChecksumMode: s3types.ChecksumModeEnabled,
	})
	if err != nil {
		if isNotFound(err) {
			return ObjectEvidence{}, false, nil
		}
		return ObjectEvidence{}, false, fmt.Errorf("audit export: %s head object: %w", s.config.ID, err)
	}
	expectedChecksum := base64.StdEncoding.EncodeToString(artifact.SHA256[:])
	observed, decodeErr := decodeSHA256(head.ChecksumSHA256)
	conflict := func(reason string) (ObjectEvidence, bool, error) {
		return ObjectEvidence{}, true, &ConflictError{
			SinkID: s.config.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256, ObservedSHA256: observed,
			Reason: reason,
		}
	}
	if decodeErr != nil || head.ChecksumSHA256 == nil || *head.ChecksumSHA256 != expectedChecksum {
		return conflict("SHA256 checksum evidence differs or is absent")
	}
	if head.ContentLength == nil || *head.ContentLength != int64(len(artifact.Bytes)) {
		return conflict("content length differs")
	}
	if head.Metadata["payment-platform-sha256"] != fmt.Sprintf("%x", artifact.SHA256) ||
		head.Metadata["payment-platform-format"] != artifact.Format {
		return conflict("bound object metadata differs")
	}
	if head.ObjectLockMode != s3types.ObjectLockModeCompliance ||
		head.ObjectLockRetainUntilDate == nil || head.ObjectLockRetainUntilDate.Before(artifact.RetainUntil) {
		return conflict("COMPLIANCE retention evidence is insufficient")
	}
	if head.VersionId == nil || *head.VersionId == "" || head.ETag == nil || *head.ETag == "" {
		return conflict("version or ETag evidence is absent")
	}
	s.mu.RLock()
	providerIdentity := s.providerIdentity
	s.mu.RUnlock()
	if providerIdentity == "" {
		return ObjectEvidence{}, true, errors.New("audit export: provider identity evidence is absent")
	}
	return ObjectEvidence{
		VersionID: *head.VersionId, ETag: strings.TrimSpace(*head.ETag),
		ProviderIdentity: providerIdentity,
		RetentionUntil:   head.ObjectLockRetainUntilDate.UTC(),
	}, true, nil
}

func decodeSHA256(value *string) (*[32]byte, error) {
	if value == nil {
		return nil, errors.New("checksum absent")
	}
	raw, err := base64.StdEncoding.DecodeString(*value)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("checksum malformed")
	}
	var result [32]byte
	copy(result[:], raw)
	return &result, nil
}

func isNotFound(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "NotFound", "NoSuchKey", "404":
			return true
		}
	}
	var noSuchKey *s3types.NoSuchKey
	return errors.As(err, &noSuchKey)
}
