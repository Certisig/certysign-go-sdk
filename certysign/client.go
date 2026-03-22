// Package certysign provides the CertySign Trust Services SDK for Go.
//
// Drop-in Go equivalent of the @certysign/sdk Node.js package.
//
// Quick start:
//
//	client, err := certysign.New(certysign.Config{
//	    PublicKey: "your-api-key-id",
//	    SecretKey: "your-api-key-secret",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	doc, _ := os.ReadFile("document.pdf")
//
//	result, err := client.Sign.HashAndSign(certysign.HashAndSignRequest{
//	    Document: doc,
//	    FileName: "document.pdf",
//	})
package certysign

import "fmt"

const sdkVersion = "1.3.2"

// Environment constants.
const (
	EnvironmentProduction  = "production"
	EnvironmentStaging     = "staging"
	EnvironmentDevelopment = "development"
	EnvironmentTest        = "test"
)

var baseURLs = map[string]string{
	EnvironmentProduction:  "https://core.certysign.io",
	EnvironmentStaging:     "https://service.certysign.io",
	EnvironmentDevelopment: "http://localhost:8000",
	EnvironmentTest:        "http://localhost:8000",
}

var tsaURLs = map[string]string{
	EnvironmentProduction:  "https://tsa.certysign.io",
	EnvironmentStaging:     "https://tsa-staging.certysign.io",
	EnvironmentDevelopment: "http://localhost:5015",
	EnvironmentTest:        "http://localhost:5015",
}

// Config holds CertySignClient configuration.
type Config struct {
	// PublicKey is your API key ID (X-API-Key-Id header).
	PublicKey string
	// SecretKey is your API key secret (X-API-Key-Secret header).
	SecretKey string
	// Environment sets the target API server: "production" | "staging" | "development" | "test".
	// Ignored when BaseURL is non-empty. Default: "production".
	Environment string
	// BaseURL overrides the computed base URL completely.
	BaseURL string
	// Timeout is the HTTP request timeout in seconds. Default: 30.
	Timeout int
	// Retries is the maximum number of retry attempts for transient failures. Default: 3.
	Retries int
	// Debug enables verbose request logging to stderr.
	Debug bool
	// TSAUrl is the base URL of the TSA service for PAdES-T timestamps.
	// When set, EmbedInPDF upgrades signatures from PAdES B-B to PAdES B-T automatically.
	TSAUrl string
}

// Client is the main CertySign SDK client.
// Instantiate once per application using New().
type Client struct {
	http *httpClient

	PublicKey   string
	Environment string
	BaseURL     string
	TSAURL      string

	// Sign provides hash-based signing operations (recommended).
	Sign *HashSigningResource
	// LegacySign provides legacy document-upload signing.
	LegacySign *SigningResource
	// Certificates provides certificate lifecycle management.
	Certificates *CertificateResource
	// PKI provides CRL, OCSP, chain, and info access.
	PKI *PKIResource
	// Envelopes provides signature envelope management.
	Envelopes *EnvelopeResource
	// Sessions provides OTP-verified signing session management.
	Sessions *SigningSessionResource
	// Dashboard provides analytics and reporting.
	Dashboard *DashboardResource
	// Hasher provides local document hashing (no network required).
	Hasher *DocumentHasher
	// Embedder provides local signature embedding (no network required).
	Embedder *SignatureEmbedder
}

// New creates and returns a new CertySign SDK Client.
func New(cfg Config) (*Client, error) {
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("certysign: PublicKey is required")
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("certysign: SecretKey is required")
	}

	env := cfg.Environment
	if env == "" {
		env = EnvironmentProduction
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		u, ok := baseURLs[env]
		if !ok {
			return nil, fmt.Errorf(
				"certysign: unknown environment %q (expected one of: %s, %s, %s, %s or provide BaseURL)",
				env,
				EnvironmentProduction,
				EnvironmentStaging,
				EnvironmentDevelopment,
				EnvironmentTest,
			)
		}
		baseURL = u
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	retries := cfg.Retries
	if retries <= 0 {
		retries = 3
	}

	resolvedTSAURL := cfg.TSAUrl
	if resolvedTSAURL == "" {
		resolvedTSAURL = tsaURLs[env]
	}

	hc := newHTTPClient(cfg.PublicKey, cfg.SecretKey, baseURL, timeout, retries, cfg.Debug)

	c := &Client{
		http:         hc,
		PublicKey:    cfg.PublicKey,
		Environment:  env,
		BaseURL:      baseURL,
		TSAURL:       resolvedTSAURL,
		Sign:         newHashSigningResource(hc),
		LegacySign:   newSigningResource(hc),
		Certificates: newCertificateResource(hc),
		PKI:          newPKIResource(hc),
		Envelopes:    newEnvelopeResource(hc),
		Sessions:     newSigningSessionResource(hc),
		Dashboard:    newDashboardResource(hc),
		Hasher:       newDocumentHasher(),
		Embedder:     newSignatureEmbedder(resolvedTSAURL),
	}

	return c, nil
}

// String implements fmt.Stringer.
func (c *Client) String() string {
	return fmt.Sprintf("certysign.Client{BaseURL: %q}", c.http.baseURL)
}

// Ping verifies that the API key can reach the PKI info endpoint.
func (c *Client) Ping() map[string]interface{} {
	result, err := c.PKI.Info()
	if err != nil {
		resp := map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
		if apiErr, ok := err.(*CertySignError); ok {
			resp["code"] = apiErr.Code
		}
		return resp
	}

	data := map[string]interface{}{}
	if raw, ok := result["data"].(map[string]interface{}); ok {
		data["keyName"] = raw["keyName"]
		data["permissions"] = raw["permissions"]
		if env, ok := raw["environment"]; ok {
			data["environment"] = env
		} else {
			data["environment"] = c.Environment
		}
		data["tenantId"] = raw["tenantId"]
		if status, ok := raw["status"].(map[string]interface{}); ok {
			data["caInitialized"] = status["initialized"]
		}
	} else {
		data["environment"] = c.Environment
	}

	return map[string]interface{}{
		"success": true,
		"data":    data,
	}
}
