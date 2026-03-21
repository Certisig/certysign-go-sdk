package certysign

import "fmt"

// CertySignError is returned by all SDK methods on failure.
type CertySignError struct {
	// Message is the human-readable error description.
	Message string
	// StatusCode is the HTTP response status code (0 for network errors).
	StatusCode int
	// Code is the machine-readable error code from the API (e.g. "INVALID_API_KEY").
	Code string
	// Details contains the full error response body from the API.
	Details map[string]interface{}
}

// Error implements the error interface.
func (e *CertySignError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("[%d] %s (code: %s)", e.StatusCode, e.Message, e.Code)
	}
	return e.Message
}

func newAPIError(message string, statusCode int, code string, details map[string]interface{}) *CertySignError {
	return &CertySignError{
		Message:    message,
		StatusCode: statusCode,
		Code:       code,
		Details:    details,
	}
}
