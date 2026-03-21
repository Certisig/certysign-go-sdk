package certysign

import "fmt"

// HashSigningResource handles hash-based signing operations.
// Documents never leave the subscriber's infrastructure — only hashes are transmitted.
type HashSigningResource struct {
	http   *httpClient
	hasher *DocumentHasher
}

func newHashSigningResource(hc *httpClient) *HashSigningResource {
	return &HashSigningResource{
		http:   hc,
		hasher: newDocumentHasher(),
	}
}

// HashAndSignRequest holds the payload for HashAndSign / SignHash.
type HashAndSignRequest struct {
	// Document is hashed locally before the request is sent.
	// It is ignored during JSON encoding.
	Document []byte `json:"-"`
	// DocumentHash is the hex-encoded hash of the document (required).
	DocumentHash string `json:"documentHash"`
	// HashAlgorithm is the hashing algorithm: "sha256" | "sha384" | "sha512".
	// Default: "sha256".
	HashAlgorithm string `json:"hashAlgorithm,omitempty"`
	// FileName is the document file name (for display and record keeping).
	FileName string `json:"fileName,omitempty"`
	// Reason is the signing reason (e.g. "Contract approval").
	Reason string `json:"reason,omitempty"`
	// Location is the physical signing location (e.g. "Nairobi, Kenya").
	Location string `json:"location,omitempty"`
	// SignerName is the full name of the signer.
	SignerName string `json:"signerName,omitempty"`
	// SignerEmail is the email address of the signer.
	SignerEmail string `json:"signerEmail,omitempty"`
	// SignatureAlgorithm is the signing algorithm (e.g. "SHA256withRSA").
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	// CertSerialNumber pins signing to a specific active certificate.
	CertSerialNumber string `json:"certSerialNumber,omitempty"`
	// Standard is the signature standard label (e.g. "PAdES Baseline B-B").
	Standard string `json:"standard,omitempty"`
	// Metadata is arbitrary caller-supplied metadata stored with the record.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// BatchHashAndSignRequest holds the payload for BatchHashAndSign.
type BatchHashAndSignRequest struct {
	// Documents is a list of {documentHash, hashAlgorithm, ...} entries.
	Documents []HashAndSignRequest `json:"documents"`
	// DefaultHashAlgorithm applies to entries that omit HashAlgorithm.
	DefaultHashAlgorithm string `json:"defaultHashAlgorithm,omitempty"`
	// Reason is the signing reason applied to the batch.
	Reason string `json:"reason,omitempty"`
	// SignerName is the full name of the signer.
	SignerName string `json:"signerName,omitempty"`
	// SignerEmail is the email address of the signer.
	SignerEmail string `json:"signerEmail,omitempty"`
	// Metadata is arbitrary caller-supplied metadata stored with the batch record.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// CertSerialNumber pins all signings to a specific certificate.
	CertSerialNumber string `json:"certSerialNumber,omitempty"`
}

// HashAndSign hashes a document locally when Document is provided, then submits the hash for signing.
//
// POST /sdk/v1/sign/hash
func (r *HashSigningResource) HashAndSign(req HashAndSignRequest) (map[string]interface{}, error) {
	payload, err := r.prepareHashAndSignPayload(req, "HashAndSign")
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/sign/hash", payload, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SignHash submits a precomputed document hash for signing.
//
// POST /sdk/v1/sign/hash
func (r *HashSigningResource) SignHash(req HashAndSignRequest) (map[string]interface{}, error) {
	req = applyHashSigningDefaults(req)
	if req.DocumentHash == "" {
		return nil, fmt.Errorf("certysign: SignHash: DocumentHash is required")
	}
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/sign/hash", req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BatchHashAndSign hashes documents locally when needed, then submits the hashes in a single call.
//
// POST /sdk/v1/sign/hash/batch
func (r *HashSigningResource) BatchHashAndSign(req BatchHashAndSignRequest) (map[string]interface{}, error) {
	if len(req.Documents) == 0 {
		return nil, fmt.Errorf("certysign: BatchHashAndSign: Documents is required and must not be empty")
	}
	if req.Reason == "" {
		req.Reason = "Batch digital signature"
	}
	defaultAlgorithm := req.DefaultHashAlgorithm
	if defaultAlgorithm == "" {
		defaultAlgorithm = "sha256"
	}
	preparedDocs := make([]HashAndSignRequest, 0, len(req.Documents))
	for i, doc := range req.Documents {
		if doc.HashAlgorithm == "" {
			doc.HashAlgorithm = defaultAlgorithm
		}
		if doc.FileName == "" {
			doc.FileName = "document.pdf"
		}
		payload, err := r.prepareHashAndSignPayload(doc, fmt.Sprintf("BatchHashAndSign[%d]", i))
		if err != nil {
			return nil, err
		}
		preparedDocs = append(preparedDocs, payload)
	}
	req.Documents = preparedDocs
	req.DefaultHashAlgorithm = defaultAlgorithm
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/sign/hash/batch", req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BatchSignHashes submits multiple precomputed hashes in a single call.
//
// POST /sdk/v1/sign/hash/batch
func (r *HashSigningResource) BatchSignHashes(req BatchHashAndSignRequest) (map[string]interface{}, error) {
	if len(req.Documents) == 0 {
		return nil, fmt.Errorf("certysign: BatchSignHashes: Documents is required and must not be empty")
	}
	if req.Reason == "" {
		req.Reason = "Batch digital signature"
	}
	for i := range req.Documents {
		if req.Documents[i].DocumentHash == "" {
			return nil, fmt.Errorf("certysign: BatchSignHashes[%d]: DocumentHash is required", i)
		}
		if req.Documents[i].HashAlgorithm == "" {
			req.Documents[i].HashAlgorithm = "sha256"
		}
	}
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/sign/hash/batch", req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyByID retrieves a signing record and verifies its integrity.
//
// GET /sdk/v1/verify/{envelopeID}
func (r *HashSigningResource) VerifyByID(envelopeID string) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: VerifyByID: envelopeID is required")
	}
	var result map[string]interface{}
	if err := r.http.get(fmt.Sprintf("/sdk/v1/verify/%s", envelopeID), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *HashSigningResource) prepareHashAndSignPayload(req HashAndSignRequest, op string) (HashAndSignRequest, error) {
	req = applyHashSigningDefaults(req)
	if len(req.Document) > 0 {
		hashResult, err := r.hasher.Hash(req.Document, req.HashAlgorithm)
		if err != nil {
			return HashAndSignRequest{}, fmt.Errorf("certysign: %s: %w", op, err)
		}
		req.DocumentHash = hashResult.Hash
	}
	if req.DocumentHash == "" {
		return HashAndSignRequest{}, fmt.Errorf("certysign: %s: Document or DocumentHash is required", op)
	}
	return req, nil
}

func applyHashSigningDefaults(req HashAndSignRequest) HashAndSignRequest {
	if req.HashAlgorithm == "" {
		req.HashAlgorithm = "sha256"
	}
	if req.FileName == "" {
		req.FileName = "document.pdf"
	}
	if req.Reason == "" {
		req.Reason = "Digital signature"
	}
	if req.Location == "" {
		req.Location = "Nairobi, Kenya"
	}
	return req
}
