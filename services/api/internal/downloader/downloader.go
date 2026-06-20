package downloader

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/netutil"
)

const (
	DefaultMaxDownloadSize = 10 * 1024 * 1024
	DefaultTimeout         = 30 * time.Second
	DefaultMaxAttempts     = 3
	DefaultRetryDelay      = 1 * time.Second
	DefaultMaxRedirects    = 5
)

var ErrDownloadTooLarge = errors.New("download exceeds maximum allowed size")

type DownloadResult struct {
	Body          io.ReadCloser
	ContentType   string
	ContentLength int64
	Headers       http.Header
	StatusCode    int
	FinalURL      string
}

type Downloader interface {
	Download(ctx context.Context, targetURL string) (*DownloadResult, error)
}

type Options struct {
	MaxSize            int64
	Timeout            time.Duration
	MaxAttempts        int
	RetryDelay         time.Duration
	MaxRedirects       int
	AllowInternalHosts bool
}

type DefaultDownloader struct {
	log     *slog.Logger
	client  *http.Client
	options Options
}

func NewDefaultDownloader(log *slog.Logger) *DefaultDownloader {
	return New(log, Options{})
}

func New(log *slog.Logger, options Options) *DefaultDownloader {
	options = withDefaults(options)

	d := &DefaultDownloader{
		log:     log,
		options: options,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&safeDialer{
			dialer: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}),
			allowInternalHosts: options.AllowInternalHosts,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	d.client = &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}

			return d.validateURL(req.URL)
		},
	}

	return d
}

func (d *DefaultDownloader) Download(ctx context.Context, targetURL string) (*DownloadResult, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	if err := d.validateURL(parsedURL); err != nil {
		return nil, err
	}

	var lastErr error

	for attempt := 1; attempt <= d.options.MaxAttempts; attempt++ {
		if attempt > 1 {
			d.log.Info("retrying download", slog.String("url", targetURL), slog.Int("attempt", attempt))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d.options.RetryDelay * time.Duration(attempt-1)):
			}
		}

		result, err := d.doDownload(ctx, targetURL)
		if err == nil {
			return result, nil
		}

		lastErr = err
		d.log.Warn("download attempt failed",
			slog.String("url", targetURL),
			slog.Int("attempt", attempt),
			slog.String("error", err.Error()),
		)

		if !isRetryable(err) {
			break
		}
	}

	return nil, fmt.Errorf("download failed after %d attempt(s): %w", d.options.MaxAttempts, lastErr)
}

func (d *DefaultDownloader) doDownload(ctx context.Context, targetURL string) (*DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "MALCORE/0.1 (+https://github.com/nijat-akhundzada/malcore)")
	req.Header.Set("Accept", "application/octet-stream,*/*;q=0.8")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, retryableError{err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		err := fmt.Errorf("server returned status: %d %s", resp.StatusCode, resp.Status)
		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, retryableError{err: err}
		}
		return nil, err
	}

	if resp.ContentLength > d.options.MaxSize {
		return nil, ErrDownloadTooLarge
	}

	body, err := readLimited(resp.Body, d.options.MaxSize)
	if err != nil {
		return nil, err
	}

	headers := resp.Header.Clone()

	return &DownloadResult{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentType:   headers.Get("Content-Type"),
		ContentLength: int64(len(body)),
		Headers:       headers,
		StatusCode:    resp.StatusCode,
		FinalURL:      resp.Request.URL.String(),
	}, nil
}

func (d *DefaultDownloader) validateURL(targetURL *url.URL) error {
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return fmt.Errorf("only http and https are supported")
	}

	host := targetURL.Hostname()
	if host == "" {
		return fmt.Errorf("url host is required")
	}

	if d.options.AllowInternalHosts {
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve host %s: %w", host, err)
	}

	for _, ip := range ips {
		if netutil.IsInternalIP(ip) {
			return fmt.Errorf("blocked internal IP: %s", ip.String())
		}
	}

	return nil
}

func readLimited(reader io.Reader, maxSize int64) ([]byte, error) {
	limited := io.LimitReader(reader, maxSize+1)

	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if int64(len(body)) > maxSize {
		return nil, ErrDownloadTooLarge
	}

	return body, nil
}

func withDefaults(options Options) Options {
	if options.MaxSize <= 0 {
		options.MaxSize = DefaultMaxDownloadSize
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.RetryDelay <= 0 {
		options.RetryDelay = DefaultRetryDelay
	}
	if options.MaxRedirects <= 0 {
		options.MaxRedirects = DefaultMaxRedirects
	}

	return options
}

type retryableError struct {
	err error
}

func (e retryableError) Error() string {
	return e.err.Error()
}

func (e retryableError) Unwrap() error {
	return e.err
}

func isRetryable(err error) bool {
	var retryable retryableError
	return errors.As(err, &retryable)
}

type safeDialer struct {
	dialer             *net.Dialer
	allowInternalHosts bool
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse dial address: %w", err)
	}

	if !d.allowInternalHosts {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve host %s: %w", host, err)
		}

		for _, ip := range ips {
			if netutil.IsInternalIP(ip) {
				return nil, fmt.Errorf("blocked internal IP: %s", ip.String())
			}
		}
	}

	return d.dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
}
