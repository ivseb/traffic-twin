package sourceclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// Response size limits.
const (
	maxHeartbeatResponse = 1 << 20
	maxPolicyResponse    = 8 << 20
)

// mtls holds the client certificate and trust anchors shared by the Fleet
// and intake HTTP clients. The certificate can be swapped after a renewal
// without rebuilding the clients: new connections pick it up.
type mtls struct {
	cert  atomic.Pointer[tls.Certificate]
	roots *x509.CertPool
	inter [][]byte // DER of the intermediates of the CA chain, sent after the leaf
}

func newMTLS(certPEM, keyPEM, caPEM []byte) (*mtls, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("sourceclient: empty CA chain")
	}
	m := &mtls{roots: roots}
	cas, err := parseCerts(caPEM)
	if err != nil {
		return nil, err
	}
	for _, c := range cas {
		// Intermediates travel with the client certificate so the server
		// can build the chain to its root.
		if !bytes.Equal(c.RawIssuer, c.RawSubject) {
			m.inter = append(m.inter, c.Raw)
		}
	}
	if err := m.setCert(certPEM, keyPEM); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *mtls) setCert(certPEM, keyPEM []byte) error {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("sourceclient: client key pair: %w", err)
	}
	c.Certificate = append(c.Certificate, m.inter...)
	m.cert.Store(&c)
	return nil
}

func (m *mtls) transport(maxIdle int) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    m.roots,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return m.cert.Load(), nil
			},
		},
		Proxy:               nil,
		MaxIdleConns:        maxIdle,
		MaxIdleConnsPerHost: maxIdle,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
	}
}

func (m *mtls) client(maxIdle int, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     m.transport(maxIdle),
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// fleetClient makes the mTLS Fleet calls.
type fleetClient struct {
	base *url.URL
	hc   *http.Client
}

func newFleetClient(fleetURL string, m *mtls, timeout time.Duration) (*fleetClient, error) {
	u, err := url.Parse(fleetURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("sourceclient: fleet url must be https")
	}
	return &fleetClient{base: u, hc: m.client(2, timeout)}, nil
}

func (f *fleetClient) do(ctx context.Context, method, path string, body []byte, hdr http.Header) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.base.JoinPath(path).String(), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, unwrapNet(err)
	}
	return resp, nil
}

// heartbeat posts a heartbeat. A 403 means the source was revoked.
func (f *fleetClient) heartbeat(ctx context.Context, hb *Heartbeat) (*HeartbeatResponse, error) {
	body, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	resp, err := f.do(ctx, http.MethodPost, "/fleet/v1/heartbeat", body, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxHeartbeatResponse))
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "heartbeat", Status: resp.StatusCode}
	}
	var hr HeartbeatResponse
	if err := json.Unmarshal(raw, &hr); err != nil {
		return nil, fmt.Errorf("sourceclient: heartbeat response: %w", errBadResponse)
	}
	return &hr, nil
}

var errBadResponse = errors.New("invalid response")

type policyResult struct {
	status int
	body   []byte
	etag   string
}

// policy fetches the assigned policy. etag is the quoted hash of the policy
// in use ("" for none).
func (f *fleetClient) policy(ctx context.Context, etag string) (*policyResult, error) {
	hdr := http.Header{}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	resp, err := f.do(ctx, http.MethodGet, "/fleet/v1/policy", nil, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &policyResult{status: resp.StatusCode, etag: resp.Header.Get("ETag")}
	if resp.StatusCode == http.StatusOK {
		r.body, err = io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponse+1))
		if err != nil {
			return nil, err
		}
		if len(r.body) > maxPolicyResponse {
			return nil, fmt.Errorf("sourceclient: policy response: %w", errBadResponse)
		}
	}
	return r, nil
}

// renew asks for a new certificate with a fresh CSR.
func (f *fleetClient) renew(ctx context.Context, csrPEM []byte) (*renewResponse, error) {
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	resp, err := f.do(ctx, http.MethodPost, "/fleet/v1/renew", body, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxHeartbeatResponse))
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Op: "renew", Status: resp.StatusCode}
	}
	var rr renewResponse
	if err := json.Unmarshal(raw, &rr); err != nil || rr.ClientCert == "" {
		return nil, errBadResponse
	}
	return &rr, nil
}
