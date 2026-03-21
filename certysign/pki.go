package certysign

import "fmt"

// PKIResource provides access to PKI infrastructure: CRL, OCSP, certificate chain, and info.
type PKIResource struct {
	http *httpClient
}

func newPKIResource(hc *httpClient) *PKIResource {
	return &PKIResource{http: hc}
}

// CRL downloads the Certificate Revocation List.
//
// GET /sdk/v1/pki/crl
//
// format: "pem" (default) | "der" | "json"
func (r *PKIResource) CRL(format string) (any, error) {
	if format == "" {
		format = "pem"
	}
	if format == "der" {
		var result []byte
		if err := r.http.getWithHeaders(
			"/sdk/v1/pki/crl",
			nil,
			map[string]string{"Accept": "application/pkix-crl"},
			&result,
		); err != nil {
			return nil, err
		}
		return result, nil
	}
	if format == "pem" {
		var result string
		if err := r.http.getWithHeaders(
			"/sdk/v1/pki/crl",
			nil,
			map[string]string{"Accept": "application/x-pem-file"},
			&result,
		); err != nil {
			return nil, err
		}
		return result, nil
	}
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/pki/crl", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// OCSP retrieves the OCSP status for a certificate serial number.
//
// GET /sdk/v1/pki/ocsp/{serialNumber}
//
// format: "json" (default) | "der"
func (r *PKIResource) OCSP(serialNumber, format string) (any, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("certysign: OCSP: serialNumber is required")
	}
	if format == "" {
		format = "json"
	}
	path := fmt.Sprintf("/sdk/v1/pki/ocsp/%s", serialNumber)
	if format == "der" {
		var result []byte
		if err := r.http.getWithHeaders(
			path,
			nil,
			map[string]string{"Accept": "application/ocsp-response"},
			&result,
		); err != nil {
			return nil, err
		}
		return result, nil
	}
	var result map[string]interface{}
	if err := r.http.get(path, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Chain downloads the CA certificate chain.
//
// GET /sdk/v1/pki/chain
func (r *PKIResource) Chain() (string, error) {
	var result string
	if err := r.http.getWithHeaders(
		"/sdk/v1/pki/chain",
		nil,
		map[string]string{"Accept": "application/x-pem-file"},
		&result,
	); err != nil {
		return "", err
	}
	return result, nil
}

// Info returns PKI configuration and status information.
//
// GET /sdk/v1/pki/info
func (r *PKIResource) Info() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/pki/info", nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}
