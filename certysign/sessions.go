package certysign

import "fmt"

// SigningSessionResource manages multi-recipient OTP-verified signing sessions.
type SigningSessionResource struct {
	http *httpClient
}

func newSigningSessionResource(hc *httpClient) *SigningSessionResource {
	return &SigningSessionResource{http: hc}
}

// CreateSessionRequest holds the payload for Create.
// Documents never leave the subscriber's system — only their hashes are sent.
type CreateSessionRequest struct {
// Name is the human-readable session name (required).
Name string `json:"name"`
// Description is an optional session description.
Description string `json:"description,omitempty"`
// Documents is the list of document hash objects:
// each must have "hash", "fileName"; optionally "hashAlgorithm", "mimeType".
Documents []map[string]interface{} `json:"documents"`
// Recipients is the list of recipients:
// each must have "email", "name"; optionally "role", "order".
Recipients []map[string]interface{} `json:"recipients"`
// SigningOrder controls recipient ordering: "sequential" | "parallel". Default: "parallel".
SigningOrder string `json:"signingOrder,omitempty"`
// ExpiresAt is an ISO 8601 UTC datetime after which the session expires.
ExpiresAt string `json:"expiresAt,omitempty"`
}

// Create creates a new signing session with document hashes and recipients.
//
// POST /sdk/v1/signing-sessions
func (r *SigningSessionResource) Create(req CreateSessionRequest) (map[string]interface{}, error) {
if req.Name == "" {
return nil, fmt.Errorf("certysign: Create: Name is required")
}
if len(req.Documents) == 0 {
return nil, fmt.Errorf("certysign: Create: Documents is required and must not be empty")
}
if len(req.Recipients) == 0 {
return nil, fmt.Errorf("certysign: Create: Recipients is required and must not be empty")
}
if req.SigningOrder == "" {
req.SigningOrder = "parallel"
}
var result map[string]interface{}
if err := r.http.post("/sdk/v1/signing-sessions", req, &result); err != nil {
return nil, err
}
return result, nil
}

// Get retrieves a signing session by ID.
//
// GET /sdk/v1/signing-sessions/{sessionID}
func (r *SigningSessionResource) Get(sessionID string) (map[string]interface{}, error) {
if sessionID == "" {
return nil, fmt.Errorf("certysign: Get: sessionID is required")
}
var result map[string]interface{}
if err := r.http.get(fmt.Sprintf("/sdk/v1/signing-sessions/%s", sessionID), nil, &result); err != nil {
return nil, err
}
return result, nil
}

// List returns a list of signing sessions matching the given filter parameters.
//
// GET /sdk/v1/signing-sessions
func (r *SigningSessionResource) List(params map[string]string) (map[string]interface{}, error) {
var result map[string]interface{}
if err := r.http.get("/sdk/v1/signing-sessions", params, &result); err != nil {
return nil, err
}
return result, nil
}

// SendOTP triggers delivery of a one-time passcode to a session recipient.
//
// POST /sdk/v1/signing-sessions/{sessionID}/recipients/{recipientID}/send-otp
func (r *SigningSessionResource) SendOTP(sessionID, recipientID string) (map[string]interface{}, error) {
if sessionID == "" {
return nil, fmt.Errorf("certysign: SendOTP: sessionID is required")
}
if recipientID == "" {
return nil, fmt.Errorf("certysign: SendOTP: recipientID is required")
}
var result map[string]interface{}
path := fmt.Sprintf("/sdk/v1/signing-sessions/%s/recipients/%s/send-otp", sessionID, recipientID)
if err := r.http.post(path, nil, &result); err != nil {
return nil, err
}
return result, nil
}

// VerifyOTP verifies the OTP submitted by a session recipient.
// On success the API returns a short-lived signingToken.
//
// POST /sdk/v1/signing-sessions/{sessionID}/recipients/{recipientID}/verify-otp
func (r *SigningSessionResource) VerifyOTP(sessionID, recipientID, code string) (map[string]interface{}, error) {
if sessionID == "" {
return nil, fmt.Errorf("certysign: VerifyOTP: sessionID is required")
}
if recipientID == "" {
return nil, fmt.Errorf("certysign: VerifyOTP: recipientID is required")
}
if code == "" {
return nil, fmt.Errorf("certysign: VerifyOTP: code is required")
}
var result map[string]interface{}
path := fmt.Sprintf("/sdk/v1/signing-sessions/%s/recipients/%s/verify-otp", sessionID, recipientID)
if err := r.http.post(path, map[string]string{"code": code}, &result); err != nil {
return nil, err
}
return result, nil
}

// RecipientSign submits the signing token for a verified recipient, triggering
// HSM signing of all session documents.
//
// POST /sdk/v1/signing-sessions/{sessionID}/recipients/{recipientID}/sign
func (r *SigningSessionResource) RecipientSign(sessionID, recipientID, signingToken string) (map[string]interface{}, error) {
if sessionID == "" {
return nil, fmt.Errorf("certysign: RecipientSign: sessionID is required")
}
if recipientID == "" {
return nil, fmt.Errorf("certysign: RecipientSign: recipientID is required")
}
if signingToken == "" {
return nil, fmt.Errorf("certysign: RecipientSign: signingToken is required")
}
var result map[string]interface{}
path := fmt.Sprintf("/sdk/v1/signing-sessions/%s/recipients/%s/sign", sessionID, recipientID)
if err := r.http.post(path, map[string]string{"signingToken": signingToken}, &result); err != nil {
return nil, err
}
return result, nil
}
