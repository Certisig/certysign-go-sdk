package certysign

import "fmt"

// EnvelopeResource manages the full lifecycle of signature envelopes.
type EnvelopeResource struct {
	http *httpClient
}

func newEnvelopeResource(hc *httpClient) *EnvelopeResource {
	return &EnvelopeResource{http: hc}
}

// EnvelopeSigner represents a signer in an envelope create request.
type EnvelopeSigner struct {
	Email  string `json:"email"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	Order  int    `json:"order,omitempty"`
	OTPReq bool   `json:"otpRequired,omitempty"`
}

// CreateEnvelopeRequest holds the payload for Create.
type CreateEnvelopeRequest struct {
	Title    string                 `json:"title"`
	Signers  []EnvelopeSigner       `json:"signers,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// EnvelopeDocument is a document to upload to an envelope.
type EnvelopeDocument struct {
	Name string
	Data []byte
}

// EnvelopeSignRequest holds the payload for Sign.
type EnvelopeSignRequest struct {
	SignerEmail  string                 `json:"signerEmail,omitempty"`
	Signatures   []map[string]interface{} `json:"signatures,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	Location     string                 `json:"location,omitempty"`
	SigningToken string                `json:"signingToken,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Create creates a new signature envelope.
//
// POST /sdk/v1/envelopes
func (r *EnvelopeResource) Create(req CreateEnvelopeRequest) (map[string]interface{}, error) {
	if req.Title == "" {
		return nil, fmt.Errorf("certysign: Create: Title is required")
	}
	var result map[string]interface{}
	if err := r.http.post("/sdk/v1/envelopes", req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Get retrieves an envelope by ID.
//
// GET /sdk/v1/envelopes/{envelopeID}
func (r *EnvelopeResource) Get(envelopeID string) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: Get: envelopeID is required")
	}
	var result map[string]interface{}
	if err := r.http.get(fmt.Sprintf("/sdk/v1/envelopes/%s", envelopeID), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// List returns a list of envelopes matching the given filter parameters.
//
// GET /sdk/v1/envelopes
func (r *EnvelopeResource) List(params map[string]string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/envelopes", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// UploadDocuments uploads one or more documents to an existing envelope.
//
// POST /sdk/v1/envelopes/{envelopeID}/documents
func (r *EnvelopeResource) UploadDocuments(envelopeID string, docs []EnvelopeDocument) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: UploadDocuments: envelopeID is required")
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("certysign: UploadDocuments: at least one document is required")
	}

	files := make([]multipartFile, 0, len(docs))
	for _, d := range docs {
		files = append(files, multipartFile{
			FieldName:   "documents",
			FileName:    d.Name,
			ContentType: mimeType(d.Name),
			Data:        d.Data,
		})
	}

	var result map[string]interface{}
	if err := r.http.postMultipart(
		fmt.Sprintf("/sdk/v1/envelopes/%s/documents", envelopeID),
		files, nil, &result,
	); err != nil {
		return nil, err
	}
	return result, nil
}

// Send dispatches the envelope to all configured signers.
//
// POST /sdk/v1/envelopes/{envelopeID}/send
func (r *EnvelopeResource) Send(envelopeID string) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: Send: envelopeID is required")
	}
	var result map[string]interface{}
	if err := r.http.post(fmt.Sprintf("/sdk/v1/envelopes/%s/send", envelopeID), nil, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Sign submits signatures for an envelope.
//
// POST /sdk/v1/envelopes/{envelopeID}/sign
func (r *EnvelopeResource) Sign(envelopeID string, req EnvelopeSignRequest) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: Sign: envelopeID is required")
	}
	if req.Reason == "" {
		req.Reason = "Digital signature"
	}
	if req.Location == "" {
		req.Location = "Nairobi, Kenya"
	}
	var result map[string]interface{}
	if err := r.http.post(fmt.Sprintf("/sdk/v1/envelopes/%s/sign", envelopeID), req, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDocument downloads a signed document from an envelope.
//
// GET /sdk/v1/envelopes/{envelopeID}/documents/{documentID}
func (r *EnvelopeResource) GetDocument(envelopeID, documentID string) ([]byte, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: GetDocument: envelopeID is required")
	}
	if documentID == "" {
		return nil, fmt.Errorf("certysign: GetDocument: documentID is required")
	}
	var result []byte
	if err := r.http.get(
		fmt.Sprintf("/sdk/v1/envelopes/%s/documents/%s", envelopeID, documentID),
		nil, &result,
	); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAuditTrail downloads the audit trail for an envelope.
//
// GET /sdk/v1/envelopes/{envelopeID}/audit
func (r *EnvelopeResource) GetAuditTrail(envelopeID string) (map[string]interface{}, error) {
	if envelopeID == "" {
		return nil, fmt.Errorf("certysign: GetAuditTrail: envelopeID is required")
	}
	var result map[string]interface{}
	if err := r.http.get(
		fmt.Sprintf("/sdk/v1/envelopes/%s/audit", envelopeID),
		nil, &result,
	); err != nil {
		return nil, err
	}
	return result, nil
}
