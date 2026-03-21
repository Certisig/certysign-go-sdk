package certysign

import (
	"fmt"
	"path/filepath"
)

// SigningResource handles legacy document-upload signing operations.
// For new integrations, prefer HashSigningResource which keeps documents local.
type SigningResource struct {
	http *httpClient
}

func newSigningResource(hc *httpClient) *SigningResource {
	return &SigningResource{http: hc}
}

// QuickSignRequest holds the payload for QuickSign.
type QuickSignRequest struct {
	// Document is the raw document bytes to sign (required).
	Document []byte
	// FileName is the document file name (required; used to detect MIME type).
	FileName string
	// SignerName is the full name of the signer (required by the API).
	SignerName string
	// SignerEmail is the email address of the signer.
	SignerEmail string
	// Reason is the signing reason.
	Reason string
	// Location is the physical signing location.
	Location string
	// Standard is the signature standard label.
	Standard string
	// CertSerialNumber pins the signing to a specific certificate.
	CertSerialNumber string
	// Metadata is caller-supplied metadata.
	Metadata map[string]interface{}
}

// BatchSignEntry is a single document entry in a batch sign request.
type BatchSignEntry struct {
	Document []byte
	FileName string
}

// BatchSignRequest holds shared metadata and documents for BatchSign.
type BatchSignRequest struct {
	// Documents is the list of documents to sign (required).
	Documents []BatchSignEntry
	// SignerName is the full name of the signer (required by the API).
	SignerName string
	// SignerEmail is the email address of the signer.
	SignerEmail string
	// Reason is the signing reason shared across all documents.
	Reason string
	// Location is the physical signing location.
	Location string
	// Metadata is caller-supplied metadata.
	Metadata map[string]interface{}
}

// QuickSign signs a single document by uploading it to the API.
//
// POST /sdk/v1/sign (multipart/form-data)
//
// Deprecated: Use HashSigningResource.HashAndSign for privacy-preserving signing.
func (r *SigningResource) QuickSign(req QuickSignRequest) (map[string]interface{}, error) {
	if len(req.Document) == 0 {
		return nil, fmt.Errorf("certysign: QuickSign: Document is required")
	}
	if req.SignerName == "" {
		return nil, fmt.Errorf("certysign: QuickSign: SignerName is required")
	}
	if req.FileName == "" {
		req.FileName = "document.pdf"
	}

	files := []multipartFile{
		{
			FieldName:   "document",
			FileName:    req.FileName,
			ContentType: mimeType(req.FileName),
			Data:        req.Document,
		},
	}

	fields := map[string]string{"signerName": req.SignerName}
	if req.SignerEmail != "" {
		fields["signerEmail"] = req.SignerEmail
	}
	reason := req.Reason
	if reason == "" {
		reason = "Digital signature"
	}
	fields["reason"] = reason
	location := req.Location
	if location == "" {
		location = "Nairobi, Kenya"
	}
	fields["location"] = location
	if req.Standard != "" {
		fields["standard"] = req.Standard
	}
	if req.CertSerialNumber != "" {
		fields["certSerialNumber"] = req.CertSerialNumber
	}

	var result map[string]interface{}
	if err := r.http.postMultipart("/sdk/v1/sign", files, fields, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BatchSign signs multiple documents in a single multipart request.
//
// POST /sdk/v1/sign/batch (multipart/form-data)
//
// Deprecated: Use HashSigningResource.BatchHashAndSign.
func (r *SigningResource) BatchSign(req BatchSignRequest) (map[string]interface{}, error) {
	if len(req.Documents) == 0 {
		return nil, fmt.Errorf("certysign: BatchSign: at least one document is required")
	}
	if req.SignerName == "" {
		return nil, fmt.Errorf("certysign: BatchSign: SignerName is required")
	}

	files := make([]multipartFile, 0, len(req.Documents))
	for _, d := range req.Documents {
		if len(d.Document) == 0 {
			return nil, fmt.Errorf("certysign: BatchSign: each entry requires Document")
		}
		if d.FileName == "" {
			d.FileName = "document.pdf"
		}
		files = append(files, multipartFile{
			FieldName:   "documents",
			FileName:    d.FileName,
			ContentType: mimeType(d.FileName),
			Data:        d.Document,
		})
	}

	fields := map[string]string{"signerName": req.SignerName}
	if req.SignerEmail != "" {
		fields["signerEmail"] = req.SignerEmail
	}
	reason := req.Reason
	if reason == "" {
		reason = "Batch digital signature"
	}
	fields["reason"] = reason
	location := req.Location
	if location == "" {
		location = "Nairobi, Kenya"
	}
	fields["location"] = location

	var result map[string]interface{}
	if err := r.http.postMultipart("/sdk/v1/sign/batch", files, fields, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyByID retrieves and verifies a signing record by its envelope ID.
//
// GET /sdk/v1/verify/{envelopeID}
func (r *SigningResource) VerifyByID(envelopeID string) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: VerifyByID: envelopeID is required")
	}
	var result map[string]interface{}
	if err := r.http.get(fmt.Sprintf("/sdk/v1/verify/%s", envelopeID), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyDocument verifies a document by uploading it for server-side verification.
//
// POST /sdk/v1/verify (multipart/form-data)
func (r *SigningResource) VerifyDocument(document []byte, filename string) (map[string]interface{}, error) {
	if len(document) == 0 {
		return nil, fmt.Errorf("certysign: VerifyDocument: document is required")
	}
	if filename == "" {
		filename = "document.pdf"
	}

	files := []multipartFile{
		{
			FieldName:   "document",
			FileName:    filename,
			ContentType: mimeType(filename),
			Data:        document,
		},
	}

	var result map[string]interface{}
	if err := r.http.postMultipart("/sdk/v1/verify", files, nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func mimeType(filename string) string {
	ext := filepath.Ext(filename)
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	case ".p7s", ".p7m":
		return "application/pkcs7-signature"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	default:
		return "application/octet-stream"
	}
}
