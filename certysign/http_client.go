package certysign

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"runtime"
	"strings"
	"time"
)

var retryableStatuses = map[int]bool{
	429: true,
	502: true,
	503: true,
	504: true,
}

type httpClient struct {
	publicKey string
	secretKey string
	baseURL   string
	timeout   time.Duration
	retries   int
	debug     bool
	client    *http.Client
}

func newHTTPClient(publicKey, secretKey, baseURL string, timeoutSeconds, retries int, debug bool) *httpClient {
	return &httpClient{
		publicKey: publicKey,
		secretKey: secretKey,
		baseURL:   strings.TrimRight(baseURL, "/"),
		timeout:   time.Duration(timeoutSeconds) * time.Second,
		retries:   retries,
		debug:     debug,
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

func (hc *httpClient) userAgent() string {
	return fmt.Sprintf("CertySign-SDK-Go/%s Go/%s", sdkVersion, runtime.Version())
}

func (hc *httpClient) newIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// request executes an HTTP request with retry + back-off logic.
func (hc *httpClient) request(method, path string, body io.Reader, extraHeaders map[string]string, idempotencyKey string) ([]byte, string, int, error) {
	if idempotencyKey == "" {
		idempotencyKey = hc.newIdempotencyKey()
	}

	url := hc.baseURL + path

	var lastErr error

	for attempt := 1; attempt <= hc.retries+1; attempt++ {
		if hc.debug {
			log.Printf("[CertySign SDK] %s %s (attempt %d)", method, path, attempt)
		}

		// Re-create body reader for retry
		var bodyReader io.Reader
		if body != nil {
			if seeker, ok := body.(io.Seeker); ok && attempt > 1 {
				if _, err := seeker.Seek(0, io.SeekStart); err != nil {
					return nil, "", 0, fmt.Errorf("certysign: body seek failed: %w", err)
				}
			}
			bodyReader = body
		}

		req, err := http.NewRequest(method, url, bodyReader)
		if err != nil {
			return nil, "", 0, fmt.Errorf("certysign: create request: %w", err)
		}

		// Auth and standard headers
		req.Header.Set("X-API-Key-Id", hc.publicKey)
		req.Header.Set("X-API-Key-Secret", hc.secretKey)
		req.Header.Set("X-Idempotency-Key", idempotencyKey)
		req.Header.Set("User-Agent", hc.userAgent())
		req.Header.Set("Accept", "application/json")

		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		resp, err := hc.client.Do(req)
		if err != nil {
			lastErr = &CertySignError{Message: err.Error(), Code: "NETWORK_ERROR"}
			if attempt <= hc.retries {
				time.Sleep(hc.retryDelay(attempt))
				continue
			}
			return nil, "", 0, lastErr
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, "", resp.StatusCode, fmt.Errorf("certysign: read response body: %w", readErr)
		}

		if retryableStatuses[resp.StatusCode] && attempt <= hc.retries {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			time.Sleep(hc.retryDelay(attempt))
			continue
		}

		if resp.StatusCode >= 400 {
			return nil, "", resp.StatusCode, hc.parseHTTPError(resp.StatusCode, respBody)
		}

		ct := resp.Header.Get("Content-Type")
		return respBody, ct, resp.StatusCode, nil
	}

	return nil, "", 0, lastErr
}

func (hc *httpClient) retryDelay(attempt int) time.Duration {
	d := time.Duration(float64(200*time.Millisecond) * math.Pow(2, float64(attempt-1)))
	if d > 4*time.Second {
		d = 4 * time.Second
	}
	return d
}

func (hc *httpClient) parseHTTPError(status int, body []byte) *CertySignError {
	var errBody map[string]interface{}
	if json.Unmarshal(body, &errBody) == nil {
		message, _ := errBody["message"].(string)
		code, _ := errBody["code"].(string)
		if message == "" {
			message = fmt.Sprintf("HTTP %d", status)
		}
		return newAPIError(message, status, code, errBody)
	}
	return newAPIError(fmt.Sprintf("HTTP %d: %s", status, strings.TrimSpace(string(body))), status, "", nil)
}

// get performs a GET request and decodes the JSON response into v.
func (hc *httpClient) get(path string, params map[string]string, v interface{}) error {
	return hc.getWithHeaders(path, params, nil, v)
}

// getWithHeaders performs a GET request with optional extra headers and decodes the response into v.
func (hc *httpClient) getWithHeaders(path string, params map[string]string, extraHeaders map[string]string, v interface{}) error {
	if len(params) > 0 {
		path = path + "?" + encodeParams(params)
	}
	body, ct, _, err := hc.request(http.MethodGet, path, nil, extraHeaders, "")
	if err != nil {
		return err
	}
	return decodeResponse(body, ct, v)
}

// post performs a POST request with a JSON body and decodes the response into v.
func (hc *httpClient) post(path string, payload interface{}, v interface{}) error {
	var bodyReader io.Reader
	headers := map[string]string{"Content-Type": "application/json"}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("certysign: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	body, ct, _, err := hc.request(http.MethodPost, path, bodyReader, headers, "")
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return decodeResponse(body, ct, v)
}

// postMultipart sends a multipart/form-data POST request.
type multipartFile struct {
	FieldName   string
	FileName    string
	ContentType string
	Data        []byte
}

func (hc *httpClient) postMultipart(path string, files []multipartFile, fields map[string]string, v interface{}) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for _, f := range files {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, f.FieldName, f.FileName))
		ct := f.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		h.Set("Content-Type", ct)
		pw, err := mw.CreatePart(h)
		if err != nil {
			return fmt.Errorf("certysign: create multipart field: %w", err)
		}
		if _, err = pw.Write(f.Data); err != nil {
			return fmt.Errorf("certysign: write multipart data: %w", err)
		}
	}

	for k, val := range fields {
		if err := mw.WriteField(k, val); err != nil {
			return fmt.Errorf("certysign: write multipart field: %w", err)
		}
	}

	_ = mw.Close()

	headers := map[string]string{"Content-Type": mw.FormDataContentType()}
	bodyReader := bytes.NewReader(buf.Bytes())
	body, ct, _, err := hc.request(http.MethodPost, path, bodyReader, headers, "")
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return decodeResponse(body, ct, v)
}

func decodeResponse(body []byte, contentType string, v interface{}) error {
	if v == nil {
		return nil
	}
	if strings.Contains(contentType, "application/json") || json.Valid(body) {
		return json.Unmarshal(body, v)
	}
	if sp, ok := v.(*string); ok {
		*sp = string(body)
		return nil
	}
	if bp, ok := v.(*[]byte); ok {
		*bp = body
		return nil
	}
	return json.Unmarshal(body, v)
}

func encodeParams(params map[string]string) string {
	var parts []string
	for k, v := range params {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}
