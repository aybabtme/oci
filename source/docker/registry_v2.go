package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
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

func (reg *Registry) newRequest(ctx context.Context, method, ref string, v interface{}) (*http.Request, error) {
	u, err := reg.resolveURL(ref)
	if err != nil {
		return nil, err
	}
	token, err := reg.tokenStore.Get(ctx)
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

func (reg *Registry) do(ctx context.Context, op string, req *http.Request, v interface{}) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, reg.tracingOpName(op), otext.SpanKindRPCClient)
	defer span.Finish()

	otext.HTTPMethod.Set(span, req.Method)
	otext.HTTPUrl.Set(span, req.URL.String())

	resp, err := reg.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	otext.HTTPStatusCode.Set(span, uint16(resp.StatusCode))

	switch resp.StatusCode {
	case http.StatusOK:
		// all is good, continue
	case http.StatusNotFound:
		return errInvalidTargetServer
	default:
		apiErr := &apiErrorBody{Code: resp.StatusCode}
		_ = json.NewDecoder(resp.Body).Decode(apiErr)
		return apiErr
	}
	if resp.Header.Get(registryVersionHeader) != registryVersionValue {
		return errInvalidTargetServer
	}
	switch vt := v.(type) {
	case io.Writer:
		_, err := io.Copy(vt, resp.Body)
		if err != nil {
			return err
		}
	case nil:
		// discard the content to be able to reuse conns, but only
		// up to 1MiB else we're wasting network resources while trying
		// to save network resources...
		_, _ = io.Copy(ioutil.Discard, io.LimitReader(resp.Body, 1<<20))
	default:
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			return err
		}
	}
	return nil
}

func (reg *Registry) rt(ctx context.Context, op, method, ref string, in, out interface{}) error {
	req, err := reg.newRequest(ctx, method, ref, in)
	if err != nil {
		return err
	}
	return reg.do(ctx, op, req, out)
}

// actual API calls

func (reg *Registry) CheckVersion(ctx context.Context) error {
	return reg.rt(ctx, "CheckVersion", "GET", "", nil, nil)
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

func computeDigest(alg DigestAlg, src io.Reader, thru func(r io.Reader) error) (Digest, error) {
	var h hash.Hash
	switch alg {
	case DigestAlgSHA256:
		h = sha256.New()
	default:
		return "", errors.New("unsupported digest algorithm")
	}
	if err := thru(io.TeeReader(src, h)); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return Digest(string(alg) + ":" + sum), nil
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
	tok           *token
}

func newTokenStore(tokenURL *url.URL, client *http.Client) *tokenStore {
	return &tokenStore{
		tokenURL:      tokenURL,
		client:        client,
		refreshBefore: 10 * time.Second,
		timeNow:       time.Now,
	}
}

func (tokStor *tokenStore) Get(ctx context.Context) (string, error) {
	tokStor.mu.Lock()
	defer tokStor.mu.Unlock()

	if tokStor.tok != nil {
		timeToRefresh := tokStor.tok.ExpiresAt().Add(-tokStor.refreshBefore)
		if tokStor.timeNow().Before(timeToRefresh) {
			// we have a token and it's still valid
			return tokStor.tok.Token, nil
		}
		// the token needs to be refreshed
	} else {
		// the token was never obtained, get a new one
	}

	req, err := http.NewRequest("GET", tokStor.tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)

	client := tokStor.client

	span, ctx := opentracing.StartSpanFromContext(ctx, "docker/registry.tokenStore.Get", otext.SpanKindRPCClient)
	defer span.Finish()

	otext.HTTPMethod.Set(span, req.Method)
	otext.HTTPUrl.Set(span, req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	otext.HTTPStatusCode.Set(span, uint16(resp.StatusCode))

	tok := new(token)
	if err := json.NewDecoder(resp.Body).Decode(tok); err != nil {
		otext.Error.Set(span, true)
		return "", err
	}
	tokStor.tok = tok
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
