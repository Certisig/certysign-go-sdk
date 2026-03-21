package certysign

import "fmt"

// CertificateResource handles certificate lifecycle operations.
type CertificateResource struct {
	http *httpClient
}

func newCertificateResource(hc *httpClient) *CertificateResource {
	return &CertificateResource{http: hc}
}

// IssueCertificateRequest holds the payload for Issue.
type IssueCertificateRequest struct {
	// CommonName is the certificate subject common name (required).
	CommonName string `json:"commonName"`
	// Organisation is the certificate holder organisation (required).
	// Note: spelt with 's' to match the CertySign API.
	Organisation string `json:"organisation"`
	// Country is the two-letter ISO 3166 country code. Default: "KE".
	Country string `json:"country,omitempty"`
	// State is the state or province. Default: "Nairobi".
	State string `json:"state,omitempty"`
	// Locality is the city or locality. Default: "Nairobi".
	Locality string `json:"locality,omitempty"`
	// Email is the certificate holder email address.
	Email string `json:"email,omitempty"`
	// ValidityDays is the certificate validity period in days. Default: 365.
	ValidityDays int `json:"validityDays,omitempty"`
	// KeySize is the RSA key size in bits. Default: 2048.
	KeySize int `json:"keySize,omitempty"`
	// Metadata is caller-supplied metadata.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Issue requests issuance of a new X.509 certificate.
//
// POST /sdk/v1/certificates/issue
func (r *CertificateResource) Issue(req IssueCertificateRequest) (map[string]interface{}, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("certysign: Issue: CommonName is required")
	}
	if req.Organisation == "" {
		return nil, fmt.Errorf("certysign: Issue: Organisation is required")
	}
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/certificates/issue", req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Verify checks the validity of a certificate by its serial number at an optional point in time.
//
// GET /sdk/v1/certificates/{serialNumber}/verify
func (r *CertificateResource) Verify(serialNumber string, atTime string) (map[string]interface{}, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("certysign: Verify: serialNumber is required")
	}
	params := map[string]string{}
	if atTime != "" {
		params["atTime"] = atTime
	}
	var result map[string]interface{}
	if err := r.http.get(fmt.Sprintf("/sdk/v1/certificates/%s/verify", serialNumber), params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Status returns the current status of a certificate.
//
// GET /sdk/v1/certificates/{serialNumber}/status
func (r *CertificateResource) Status(serialNumber string) (map[string]interface{}, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("certysign: Status: serialNumber is required")
	}
	var result map[string]interface{}
	if err := r.http.get(fmt.Sprintf("/sdk/v1/certificates/%s/status", serialNumber), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetActive returns the subscriber's currently active certificate.
//
// GET /sdk/v1/certificates/active
func (r *CertificateResource) GetActive() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/certificates/active", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
