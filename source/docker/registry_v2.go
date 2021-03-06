package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"
)

const (
	apiV2                  = "v2"
	pathComponentSeparator = "/"
	maxRepoLength          = 256

	registryVersionHeader = "Docker-Distribution-API-Version"
	registryVersionValue  = "registry/2.0"

	DefaultTokenURL        = "https://auth.docker.io/token?service=registry.docker.io"
	DefaultRegistryBaseURL = "https://registry.hub.docker.com"
	DefaultUserAgent       = "github.com/aybabtme/oci/source/docker"

	// mediaTypeManifestV1 specifies the mediaType for the current version. Note
	// that for schema version 1, the the media is optionally "application/json".
	mediaTypeManifestV1 = "application/vnd.docker.distribution.manifest.v1+json"
	// mediaTypeManifestV2 specifies the mediaType for the current version.
	mediaTypeManifestV2 = "application/vnd.docker.distribution.manifest.v2+json"
)

var (
	errRepoNameTooLong     = errors.New("repo name must be less than 256 characters")
	errInvalidComponent    = errors.New("repo name component is invalid")
	errInvalidTargetServer = errors.New("server at given URL is not a Docker Registry v2")

	componentRegexp = regexp.MustCompile(`[a-z0-9]+(?:[._-][a-z0-9]+)*`)
)

type registryOpts struct {
	tokenURL  *url.URL
	baseURL   *url.URL
	client    *http.Client
	userAgent string
	token     string
}

type Option func(*registryOpts) error

func WithTokenURL(urlStr string) Option {
	return func(opts *registryOpts) error {
		u, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		opts.tokenURL = u
		return nil
	}
}

func WithBaseURL(urlStr string) Option {
	return func(opts *registryOpts) error {
		u, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		opts.baseURL = u
		return nil
	}
}

func WithClient(client *http.Client) Option {
	return func(opts *registryOpts) error {
		opts.client = client
		return nil
	}
}

func WithUserAgent(ua string) Option {
	return func(opts *registryOpts) error {
		opts.userAgent = ua
		return nil
	}
}

func WithBearerToken(bearerToken string) Option {
	return func(opts *registryOpts) error {
		opts.token = bearerToken
		return nil
	}
}

type Registry struct {
	tokenStore *tokenStore
	baseURL    *url.URL
	client     *http.Client
	userAgent  string
}

func New(ctx context.Context, opts ...Option) (*Registry, error) {
	defOpts := &registryOpts{}
	for _, o := range append(
		[]Option{
			WithTokenURL(DefaultTokenURL),
			WithBaseURL(DefaultRegistryBaseURL),
			WithClient(&http.Client{}),
			WithUserAgent(DefaultUserAgent),
		},
		opts...,
	) {
		if err := o(defOpts); err != nil {
			return nil, err
		}
	}

	return &Registry{
		tokenStore: newTokenStore(defOpts.tokenURL, defOpts.client),
		baseURL:    defOpts.baseURL,
		client:     defOpts.client,
		userAgent:  defOpts.userAgent,
	}, nil
}

func (reg *Registry) resolveURL(ref string) (*url.URL, error) {
	return reg.baseURL.Parse(path.Join(apiV2, ref))
}

func (reg *Registry) tracingOpName(op string) string {
	return "docker/registry." + op
}

func (reg *Registry) newRequest(ctx context.Context, method, ref, scope string, v interface{}) (*http.Request, error) {
	u, err := reg.resolveURL(ref)
	if err != nil {
		return nil, err
	}
	token, err := reg.tokenStore.Get(ctx, scope)
	if err != nil {
		return nil, err
	}

	var (
		contentType = ""
		body        io.Reader
	)
	switch vt := v.(type) {
	case nil:
		// do nothing
	case io.Reader:
		body = vt
	default:
		buf := bytes.NewBuffer(nil)
		if err := json.NewEncoder(buf).Encode(v); err != nil {
			return nil, err
		}
		body = buf
		contentType = "application/json"
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// mandatory headers
	req.Header.Set("Authorization", "Bearer "+token)
	// optional headers
	setIfValue := func(k, v string) {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	setIfValue("User-Agent", reg.userAgent)
	setIfValue("Content-Type", contentType)
	req = req.WithContext(ctx)
	return req, nil
}

func (reg *Registry) do(ctx context.Context, op string, req *http.Request, v interface{}) (bool, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, reg.tracingOpName(op), otext.SpanKindRPCClient)
	defer span.Finish()

	otext.HTTPMethod.Set(span, req.Method)
	otext.HTTPUrl.Set(span, req.URL.String())

	log.Printf(req.URL.String())

	resp, err := reg.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	otext.HTTPStatusCode.Set(span, uint16(resp.StatusCode))

	switch resp.StatusCode {
	case http.StatusOK:
		// all is good, continue
	case http.StatusNotFound:
		return false, nil
	default:
		apiErr := &apiErrorBody{Code: resp.StatusCode}
		_ = json.NewDecoder(resp.Body).Decode(apiErr)
		return false, apiErr
	}

	// if we're not redirected, check proper API version
	if resp.Request.Host == req.Host && resp.Header.Get("Content-Type") != "application/octet-stream" {
		if resp.Header.Get(registryVersionHeader) != registryVersionValue {
			return false, errInvalidTargetServer
		}
	}

	switch vt := v.(type) {
	case io.Writer:
		_, err := io.Copy(vt, resp.Body)
		if err != nil {
			return false, err
		}
	case nil:
		// discard the content to be able to reuse conns, but only
		// up to 1MiB else we're wasting network resources while trying
		// to save network resources...
		_, _ = io.Copy(ioutil.Discard, io.LimitReader(resp.Body, 1<<20))
	default:
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (reg *Registry) rt(ctx context.Context, op, method, ref, scope string, in, out interface{}) (bool, error) {
	req, err := reg.newRequest(ctx, method, ref, scope, in)
	if err != nil {
		return false, err
	}
	return reg.do(ctx, op, req, out)
}

// actual API calls

func (reg *Registry) CheckVersion(ctx context.Context) error {
	ok, err := reg.rt(ctx, "CheckVersion", "GET", "", "", nil, nil)
	if err != nil {
		return err
	}
	if !ok {
		return errInvalidTargetServer
	}
	return nil
}

func (reg *Registry) GetImageManifest(ctx context.Context, name, tag string) (*ImageManifest, bool, error) {
	path := path.Join(name, "manifests", tag)
	scope := strings.Join([]string{
		"repository",
		name,
		"pull",
	}, ":")

	outBytes := bytes.NewBuffer(nil)
	if found, err := reg.rt(ctx, "GetImageManifest", "GET", path, scope, nil, outBytes); err != nil {
		return nil, false, err
	} else if !found {
		return nil, false, nil
	}

	v1Schema := new(ImageManifestV1)
	v2Schema := new(ImageManifestV2)
	v1err := json.Unmarshal(outBytes.Bytes(), v1Schema)
	v2err := json.Unmarshal(outBytes.Bytes(), v2Schema)

	if v1err != nil && v2err != nil {
		return nil, false, v1err
	}

	if v1Schema.SchemaVersion != v2Schema.SchemaVersion {
		return nil, false, errors.New("invalid schema version")
	}

	version := v1Schema.SchemaVersion
	switch version {
	case 1:
		return &ImageManifest{Name: name, Tag: tag, V1: v1Schema}, true, v1err

	case 2:
		return &ImageManifest{Name: name, Tag: tag, V2: v2Schema}, true, v2err

	default:
		return nil, false, errors.New("invalid schema version")
	}
}

func (reg *Registry) GetImageLayer(ctx context.Context, name string, dg Digest, w io.Writer) (bool, error) {
	path := path.Join(name, "blobs", string(dg))
	scope := strings.Join([]string{
		"repository",
		name,
		"pull",
	}, ":")

	var (
		found bool
		err   error
	)
	err = validateContent(dg, w, func(checkedW io.Writer) error {
		found, err = reg.rt(ctx, "GetImageLayer", "GET", path, scope, nil, checkedW)
		return err
	})
	return found, err
}

// details

type DigestAlg string

const (
	DigestAlgInvalid = ""
	DigestAlgSHA256  = "sha256"
)

type Digest string

func ParseDigest(str string) (Digest, error) {
	d := Digest(str)
	return d, d.Validate()
}

func (d Digest) Validate() error {
	if d.Alg() == DigestAlgInvalid {
		return errors.New("invalid algorithm part")
	}
	_, err := d.sum()
	return err
}

func (d Digest) Alg() DigestAlg {
	parts := strings.Split(string(d), ":")
	if len(parts) != 2 {
		return DigestAlgInvalid
	}
	switch parts[0] {
	case DigestAlgSHA256:
		return DigestAlgSHA256
	default:
		return DigestAlgInvalid
	}
}

func (d Digest) Sum() []byte {
	s, err := d.sum()
	if err != nil {
		panic(err)
	}
	return s
}

func (d Digest) sum() ([]byte, error) {
	parts := strings.Split(string(d), ":")
	if len(parts) != 2 {
		return nil, errors.New("malformed digest, need to be of the form \"alg:sum\"")
	}
	return hex.DecodeString(parts[1])
}

func validateContent(dg Digest, w io.Writer, thru func(w io.Writer) error) error {
	if err := dg.Validate(); err != nil {
		return err
	}
	alg := dg.Alg()
	var h hash.Hash
	switch alg {
	case DigestAlgSHA256:
		h = sha256.New()
	default:
		return errors.New("unsupported digest algorithm")
	}

	if err := thru(io.MultiWriter(w, h)); err != nil {
		return err
	}
	got := Digest(string(alg) + ":" + hex.EncodeToString(h.Sum(nil)))

	if got != dg {
		return errors.New("received content doesn't match expected digest")
	}

	return nil
}

func parsePathComponents(repo string) ([]string, error) {
	// A repository name is broken up into path components. A component of a repository name must be at least one lowercase,
	// alpha-numeric characters, optionally separated by periods, dashes or underscores. More strictly, it must match the
	// regular expression [a-z0-9]+(?:[._-][a-z0-9]+)*.
	// If a repository name has two or more path components, they must be separated by a forward slash (“/”).
	// The total length of a repository name, including slashes, must be less than 256 characters.

	if len(repo) >= maxRepoLength {
		return nil, errRepoNameTooLong
	}
	components := strings.Split(repo, pathComponentSeparator)
	for _, component := range components {
		if !componentRegexp.MatchString(component) {
			return nil, errInvalidComponent
		}
	}
	return components, nil
}

type apiErrorBody struct {
	Code   int         `json:"-"`
	Errors []*apiError `json:"errors"`
}

func (apiErr *apiErrorBody) Error() string {
	return fmt.Sprintf("API responded with %d: %v", apiErr.Code, apiErr.Errors)
}

type apiError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail"`
}

func (apiErr *apiError) Error() string {
	return fmt.Sprintf("%s: %s", apiErr.Code, apiErr.Message)
}

// hack

type tokenStore struct {
	tokenURL *url.URL
	client   *http.Client

	mu            sync.Mutex
	timeNow       func() time.Time
	refreshBefore time.Duration
	tok           map[string]*token
}

func newTokenStore(tokenURL *url.URL, client *http.Client) *tokenStore {
	return &tokenStore{
		tokenURL:      tokenURL,
		client:        client,
		refreshBefore: 10 * time.Second,
		timeNow:       time.Now,
		tok:           make(map[string]*token),
	}
}

func (tokStor *tokenStore) Get(ctx context.Context, scope string) (string, error) {
	tokStor.mu.Lock()
	defer tokStor.mu.Unlock()

	tok, ok := tokStor.tok[scope]
	if ok {
		timeToRefresh := tok.ExpiresAt().Add(-tokStor.refreshBefore)
		if tokStor.timeNow().Before(timeToRefresh) {
			// we have a token and it's still valid
			return tok.Token, nil
		}
		// the token needs to be refreshed
	} else {
		// the token was never obtained, get a new one
	}

	u := tokStor.tokenURL
	dup := url.URL{
		Scheme:     u.Scheme,
		Opaque:     u.Opaque,
		User:       u.User,
		Host:       u.Host,
		Path:       u.Path,
		RawPath:    u.RawPath,
		ForceQuery: u.ForceQuery,
		RawQuery:   u.RawQuery,
		Fragment:   u.Fragment,
	}
	if scope != "" {
		q := dup.Query()
		q.Add("scope", scope)
		dup.RawQuery = q.Encode()
	}

	req, err := http.NewRequest("GET", dup.String(), nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)

	client := tokStor.client

	span, ctx := opentracing.StartSpanFromContext(ctx, "docker/registry.tokenStore.Get", otext.SpanKindRPCClient)
	defer span.Finish()

	span = span.SetTag("scope", scope)
	otext.HTTPMethod.Set(span, req.Method)
	otext.HTTPUrl.Set(span, req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	otext.HTTPStatusCode.Set(span, uint16(resp.StatusCode))

	tok = new(token)
	if err := json.NewDecoder(resp.Body).Decode(tok); err != nil {
		otext.Error.Set(span, true)
		return "", err
	}
	tokStor.tok[scope] = tok
	return tok.Token, nil
}

type token struct {
	Token     string    `json:"token"`
	ExpiresIn int       `json:"expires_in"`
	IssuedAt  time.Time `json:"issued_at"`
}

func (tok *token) ExpiresAt() time.Time {
	return tok.IssuedAt.Add(time.Duration(tok.ExpiresIn) * time.Second)
}
