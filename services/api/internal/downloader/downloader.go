package downloader

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/netutil"
)

const (
	MaxDownloadSize = 10 * 1024 * 1024 // 10MB
	DefaultTimeout  = 30 * time.Second
	MaxRetries      = 3
	RetryDelay      = 1 * time.Second
)

type DownloadResult struct {
	Body          io.ReadCloser
	ContentType   string
	ContentLength int64
	Headers       http.Header
}

type Downloader interface {
	Download(ctx context.Context, url string) (*DownloadResult, error)
}

type DefaultDownloader struct {
	log    *slog.Logger
	client *http.Client
}

func NewDefaultDownloader(log *slog.Logger) *DefaultDownloader {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Explicitly disable HTTP/2 for better compatibility with strict sites
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	return &DefaultDownloader{
		log: log,
		client: &http.Client{
			Transport: tr,
			Timeout:   DefaultTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func (d *DefaultDownloader) Download(ctx context.Context, targetURL string) (*DownloadResult, error) {
	var lastErr error

	for attempt := 1; attempt <= MaxRetries; attempt++ {
		if attempt > 1 {
			d.log.Info("retrying download", slog.String("url", targetURL), slog.Int("attempt", attempt))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(RetryDelay * time.Duration(attempt-1)):
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
	}

	return nil, fmt.Errorf("after %d attempts, failed to download: %w", MaxRetries, lastErr)
}

func (d *DefaultDownloader) doDownload(ctx context.Context, targetURL string) (*DownloadResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Browser-like User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")

	// SSRF Protection: Resolve hostname first
	host := req.URL.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %s: %w", host, err)
	}

	for _, ip := range ips {
		if netutil.IsInternalIP(ip) {
			return nil, fmt.Errorf("blocked internal IP: %s", ip.String())
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned status: %d %s", resp.StatusCode, resp.Status)
	}

	// Use LimitReader to enforce size limit
	result := &DownloadResult{
		Body:          &limitClocser{r: io.LimitReader(resp.Body, MaxDownloadSize), c: resp.Body},
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Headers:       resp.Header,
	}

	return result, nil
}

type limitClocser struct {
	r io.Reader
	c io.Closer
}

func (l *limitClocser) Read(p []byte) (n int, err error) {
	return l.r.Read(p)
}

func (l *limitClocser) Close() error {
	return l.c.Close()
}
