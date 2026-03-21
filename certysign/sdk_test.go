package certysign_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	certysign "github.com/certysign/sdk-go/certysign"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestClient returns a Client pointed at the given test-server URL.
func newTestClient(t *testing.T, baseURL string) *certysign.Client {
	t.Helper()
	c, err := certysign.New(certysign.Config{
		PublicKey: "test-pub-key",
		SecretKey: "test-sec-key",
		BaseURL:   baseURL,
		Retries:   0, // avoid sleeps in unit tests
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return c
}

func newLocalServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = listener
	srv.Start()
	return srv
}

// jsonResponse writes a JSON response to w.
func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readBody decodes JSON body into a map.
func readBody(r *http.Request) map[string]interface{} {
	var m map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

// ---------------------------------------------------------------------------
// 1. Client construction
// ---------------------------------------------------------------------------

func TestUnit_NewClientValidation(t *testing.T) {
	_, err := certysign.New(certysign.Config{})
	if err == nil {
		t.Fatal("expected error when PublicKey is empty")
	}

	_, err = certysign.New(certysign.Config{PublicKey: "pk"})
	if err == nil {
		t.Fatal("expected error when SecretKey is empty")
	}

	c, err := certysign.New(certysign.Config{PublicKey: "pk", SecretKey: "sk"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestUnit_EnvironmentURLs(t *testing.T) {
	cases := []struct {
		env  string
		want string
	}{
		{certysign.EnvironmentProduction, "https://core.certysign.io"},
		{certysign.EnvironmentStaging, "https://service.certysign.io"},
		{certysign.EnvironmentDevelopment, "http://localhost:8000"},
		{certysign.EnvironmentTest, "http://localhost:8000"},
	}
	for _, tc := range cases {
		c, err := certysign.New(certysign.Config{
			PublicKey:   "pk",
			SecretKey:   "sk",
			Environment: tc.env,
		})
		if err != nil {
			t.Fatalf("env %s: New() error: %v", tc.env, err)
		}
		if !strings.Contains(c.String(), tc.want) {
			t.Errorf("env %s: expected %q in %q", tc.env, tc.want, c.String())
		}
		if c.BaseURL != tc.want {
			t.Errorf("env %s: BaseURL = %q, want %q", tc.env, c.BaseURL, tc.want)
		}
	}
}

func TestUnit_UnknownEnvironment(t *testing.T) {
	_, err := certysign.New(certysign.Config{
		PublicKey:   "pk",
		SecretKey:   "sk",
		Environment: "qa",
	})
	if err == nil {
		t.Fatal("expected error for unknown environment")
	}
}

// ---------------------------------------------------------------------------
// 2. Auth headers
// ---------------------------------------------------------------------------

func TestUnit_AuthHeaders(t *testing.T) {
	gotPub := ""
	gotSec := ""
	gotIdem := ""

	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPub = r.Header.Get("X-API-Key-Id")
		gotSec = r.Header.Get("X-API-Key-Secret")
		gotIdem = r.Header.Get("X-Idempotency-Key")
		jsonResponse(w, 200, map[string]interface{}{"ok": true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _ = c.Dashboard.GetStats(nil)

	if gotPub != "test-pub-key" {
		t.Errorf("X-API-Key-Id = %q, want %q", gotPub, "test-pub-key")
	}
	if gotSec != "test-sec-key" {
		t.Errorf("X-API-Key-Secret = %q, want %q", gotSec, "test-sec-key")
	}
	if gotIdem == "" {
		t.Error("X-Idempotency-Key must not be empty")
	}
}

func TestUnit_PingSuccess(t *testing.T) {
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/v1/pki/info" {
			t.Errorf("path = %s, want /sdk/v1/pki/info", r.URL.Path)
		}
		jsonResponse(w, 200, map[string]interface{}{
			"data": map[string]interface{}{
				"keyName":     "SDK Key",
				"permissions": []interface{}{"pki:info"},
				"environment": "staging",
				"tenantId":    "tenant_123",
				"status": map[string]interface{}{
					"initialized": true,
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result := c.Ping()
	if result["success"] != true {
		t.Fatalf("Ping success = %v, want true", result["success"])
	}
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Ping data type = %T", result["data"])
	}
	if data["keyName"] != "SDK Key" {
		t.Errorf("keyName = %v", data["keyName"])
	}
	if data["caInitialized"] != true {
		t.Errorf("caInitialized = %v", data["caInitialized"])
	}
}

func TestUnit_PingFailure(t *testing.T) {
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 401, map[string]interface{}{
			"message": "Unauthorized",
			"code":    "AUTH_REQUIRED",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result := c.Ping()
	if result["success"] != false {
		t.Fatalf("Ping success = %v, want false", result["success"])
	}
	if result["code"] != "AUTH_REQUIRED" {
		t.Errorf("code = %v, want AUTH_REQUIRED", result["code"])
	}
}

// ---------------------------------------------------------------------------
// 3. Hasher — no network required
// ---------------------------------------------------------------------------

func TestUnit_HasherHash(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	data := []byte("hello certysign")
	result, err := c.Hasher.Hash(data, "")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:]) // lowercase hex
	if result.Hash != want {
		t.Errorf("Hash = %q, want %q", result.Hash, want)
	}
	if result.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want %q", result.Algorithm, "sha256")
	}
	if result.Size != int64(len(data)) {
		t.Errorf("Size = %d, want %d", result.Size, len(data))
	}
}

func TestUnit_HasherHashExplicitAlgorithm(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})
	result, err := c.Hasher.Hash([]byte("data"), "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if result.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", result.Algorithm)
	}
	if strings.ToUpper(result.Hash) == result.Hash && len(result.Hash) > 0 {
		t.Error("Hash should be lowercase hex")
	}
}

func TestUnit_HasherHashEmpty(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})
	_, err := c.Hasher.Hash([]byte{}, "")
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestUnit_HasherHashFile(t *testing.T) {
	f, _ := os.CreateTemp("", "certysign-test-*.bin")
	data := []byte("file content for hashing")
	_, _ = f.Write(data)
	_ = f.Close()
	defer os.Remove(f.Name())

	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	result, err := c.Hasher.HashFile(f.Name(), "")
	if err != nil {
		t.Fatalf("HashFile() error: %v", err)
	}

	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if result.Hash != want {
		t.Errorf("Hash = %q, want %q", result.Hash, want)
	}
	if result.FileName == "" {
		t.Error("FileName must be set when hashing a file")
	}
	if result.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", result.Algorithm)
	}
}

func TestUnit_HasherHashMany(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	docs := []certysign.HashDocument{
		{Data: []byte("doc1"), FileName: "doc1.pdf"},
		{Data: []byte("doc2"), FileName: "doc2.pdf"},
		{Data: []byte("doc3"), FileName: "doc3.pdf"},
	}
	results, err := c.Hasher.HashMany(docs, "")
	if err != nil {
		t.Fatalf("HashMany() error: %v", err)
	}
	if len(results) != len(docs) {
		t.Errorf("len(results) = %d, want %d", len(results), len(docs))
	}
	for i, res := range results {
		sum := sha256.Sum256(docs[i].Data)
		want := hex.EncodeToString(sum[:])
		if res.Hash != want {
			t.Errorf("doc[%d] hash = %q, want %q", i, res.Hash, want)
		}
		if res.FileName != docs[i].FileName {
			t.Errorf("doc[%d] fileName = %q, want %q", i, res.FileName, docs[i].FileName)
		}
	}
}

func TestUnit_HasherHashFiles(t *testing.T) {
	paths := make([]string, 3)
	expected := make([]string, 3)
	for i := 0; i < 3; i++ {
		f, _ := os.CreateTemp("", "certysign-test-*.bin")
		data := []byte(fmt.Sprintf("file content %d", i))
		_, _ = f.Write(data)
		_ = f.Close()
		paths[i] = f.Name()
		sum := sha256.Sum256(data)
		expected[i] = hex.EncodeToString(sum[:])
		defer os.Remove(f.Name())
	}

	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	results, err := c.Hasher.HashFiles(paths, "")
	if err != nil {
		t.Fatalf("HashFiles() error: %v", err)
	}
	for i, res := range results {
		if res.Hash != expected[i] {
			t.Errorf("file[%d] hash = %q, want %q", i, res.Hash, expected[i])
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Hash signing resource
// ---------------------------------------------------------------------------

func TestUnit_HashAndSign_Post(t *testing.T) {
	var got map[string]interface{}
	doc := []byte("contract bytes")
	expectedHash := sha256.Sum256(doc)
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/sdk/v1/sign/hash" {
			t.Errorf("path = %s, want /sdk/v1/sign/hash", r.URL.Path)
		}
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"id": "sign_001", "status": "pending"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sign.HashAndSign(certysign.HashAndSignRequest{
		Document: doc,
		FileName: "contract.pdf",
		Reason:   "Approval",
	})
	if err != nil {
		t.Fatalf("HashAndSign() error: %v", err)
	}
	if result["id"] != "sign_001" {
		t.Errorf("result id = %v, want sign_001", result["id"])
	}
	if got["documentHash"] != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("body documentHash = %v", got["documentHash"])
	}
	if got["hashAlgorithm"] != "sha256" {
		t.Errorf("body hashAlgorithm = %v", got["hashAlgorithm"])
	}
}

func TestUnit_HashAndSign_DefaultAlgorithm(t *testing.T) {
	var got map[string]interface{}
	doc := []byte("default algorithm test")
	expectedHash := sha256.Sum256(doc)
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"id": "x"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Sign.HashAndSign(certysign.HashAndSignRequest{Document: doc})
	if err != nil {
		t.Fatal(err)
	}
	if got["hashAlgorithm"] != "sha256" {
		t.Errorf("default hashAlgorithm = %v, want sha256", got["hashAlgorithm"])
	}
	if got["documentHash"] != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("default documentHash = %v", got["documentHash"])
	}
	if got["fileName"] != "document.pdf" {
		t.Errorf("default fileName = %v, want document.pdf", got["fileName"])
	}
	if got["reason"] != "Digital signature" {
		t.Errorf("default reason = %v, want Digital signature", got["reason"])
	}
	if got["location"] != "Nairobi, Kenya" {
		t.Errorf("default location = %v, want Nairobi, Kenya", got["location"])
	}
}

func TestUnit_HashAndSign_RequiresDocumentOrDocumentHash(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})
	_, err := c.Sign.HashAndSign(certysign.HashAndSignRequest{})
	if err == nil {
		t.Error("expected error when DocumentHash is empty")
	}
}

func TestUnit_SignHash_IsAlias(t *testing.T) {
	// SignHash must also POST to /sdk/v1/sign/hash (same endpoint as HashAndSign)
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"id": "s"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Sign.SignHash(certysign.HashAndSignRequest{DocumentHash: "aabb"})
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/sign/hash" {
		t.Errorf("SignHash path = %s, want /sdk/v1/sign/hash", hitPath)
	}
}

func TestUnit_BatchHashAndSign_Post(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/v1/sign/hash/batch" {
			t.Errorf("path = %s, want /sdk/v1/sign/hash/batch", r.URL.Path)
		}
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"results": []interface{}{}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	req := certysign.BatchHashAndSignRequest{
		Documents: []certysign.HashAndSignRequest{
			{Document: []byte("first batch doc"), FileName: "a.pdf"},
			{Document: []byte("second batch doc"), FileName: "b.pdf"},
		},
		Reason: "Batch approval",
	}
	_, err := c.Sign.BatchHashAndSign(req)
	if err != nil {
		t.Fatalf("BatchHashAndSign() error: %v", err)
	}
	docs, ok := got["documents"].([]interface{})
	if !ok || len(docs) != 2 {
		t.Errorf("expected 2 documents in batch body, got %v", got["documents"])
	}
	if got["reason"] != "Batch approval" {
		t.Errorf("reason = %v, want Batch approval", got["reason"])
	}
}

func TestUnit_BatchHashAndSign_DefaultFileNameAndReason(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"results": []interface{}{}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Sign.BatchHashAndSign(certysign.BatchHashAndSignRequest{
		Documents: []certysign.HashAndSignRequest{
			{Document: []byte("first batch doc")},
		},
	})
	if err != nil {
		t.Fatalf("BatchHashAndSign() error: %v", err)
	}
	if got["reason"] != "Batch digital signature" {
		t.Errorf("reason = %v, want Batch digital signature", got["reason"])
	}
	docs, _ := got["documents"].([]interface{})
	doc0, _ := docs[0].(map[string]interface{})
	if doc0["fileName"] != "document.pdf" {
		t.Errorf("fileName = %v, want document.pdf", doc0["fileName"])
	}
}

func TestUnit_BatchSignHashes_IsAlias(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _ = c.Sign.BatchSignHashes(certysign.BatchHashAndSignRequest{
		Documents: []certysign.HashAndSignRequest{{DocumentHash: "aa"}},
	})
	if hitPath != "/sdk/v1/sign/hash/batch" {
		t.Errorf("BatchSignHashes path = %s, want /sdk/v1/sign/hash/batch", hitPath)
	}
}

func TestUnit_VerifyByID_Get(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"valid": true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sign.VerifyByID("sign_abc")
	if err != nil {
		t.Fatalf("VerifyByID() error: %v", err)
	}
	if hitPath != "/sdk/v1/verify/sign_abc" {
		t.Errorf("path = %s, want /sdk/v1/verify/sign_abc", hitPath)
	}
	if result["valid"] != true {
		t.Errorf("result valid = %v, want true", result["valid"])
	}
}

// ---------------------------------------------------------------------------
// 5. Signing sessions resource
// ---------------------------------------------------------------------------

func TestUnit_Sessions_Create_Post(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/v1/signing-sessions" {
			t.Errorf("path = %s, want /sdk/v1/signing-sessions", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		got = readBody(r)
		jsonResponse(w, 201, map[string]interface{}{"id": "sess_001", "status": "pending"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	req := certysign.CreateSessionRequest{
		Name: "Contract Signing",
		Documents: []map[string]interface{}{
			{"hash": "aabb", "fileName": "contract.pdf"},
		},
		Recipients: []map[string]interface{}{
			{"email": "alice@example.com", "name": "Alice"},
		},
		SigningOrder: "sequential",
	}
	result, err := c.Sessions.Create(req)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if result["id"] != "sess_001" {
		t.Errorf("result id = %v, want sess_001", result["id"])
	}
	if got["name"] != "Contract Signing" {
		t.Errorf("body name = %v", got["name"])
	}
	if got["signingOrder"] != "sequential" {
		t.Errorf("body signingOrder = %v", got["signingOrder"])
	}
}

func TestUnit_Sessions_Create_DefaultSigningOrder(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = readBody(r)
		jsonResponse(w, 201, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Sessions.Create(certysign.CreateSessionRequest{
		Name:       "Test",
		Documents:  []map[string]interface{}{{"hash": "aa"}},
		Recipients: []map[string]interface{}{{"email": "a@b.com"}},
		// SigningOrder omitted → should default to "parallel"
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["signingOrder"] != "parallel" {
		t.Errorf("default signingOrder = %v, want parallel", got["signingOrder"])
	}
}

func TestUnit_Sessions_Create_Validation(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	_, err := c.Sessions.Create(certysign.CreateSessionRequest{})
	if err == nil {
		t.Error("expected error when Name is empty")
	}

	_, err = c.Sessions.Create(certysign.CreateSessionRequest{Name: "x"})
	if err == nil {
		t.Error("expected error when Documents is empty")
	}

	_, err = c.Sessions.Create(certysign.CreateSessionRequest{
		Name:      "x",
		Documents: []map[string]interface{}{{"hash": "aa"}},
	})
	if err == nil {
		t.Error("expected error when Recipients is empty")
	}
}

func TestUnit_Sessions_Get(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"id": "sess_abc"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sessions.Get("sess_abc")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/signing-sessions/sess_abc" {
		t.Errorf("path = %s", hitPath)
	}
	if result["id"] != "sess_abc" {
		t.Errorf("id = %v", result["id"])
	}
}

func TestUnit_Sessions_List(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"items": []interface{}{}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Sessions.List(map[string]string{"status": "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/signing-sessions" {
		t.Errorf("path = %s, want /sdk/v1/signing-sessions", hitPath)
	}
}

func TestUnit_Sessions_SendOTP(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"sent": true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sessions.SendOTP("sess_1", "rec_1")
	if err != nil {
		t.Fatal(err)
	}
	want := "/sdk/v1/signing-sessions/sess_1/recipients/rec_1/send-otp"
	if hitPath != want {
		t.Errorf("path = %s, want %s", hitPath, want)
	}
	if result["sent"] != true {
		t.Errorf("sent = %v", result["sent"])
	}
}

func TestUnit_Sessions_VerifyOTP(t *testing.T) {
	var hitPath string
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"signingToken": "tok_xyz"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sessions.VerifyOTP("sess_1", "rec_1", "123456")
	if err != nil {
		t.Fatal(err)
	}
	want := "/sdk/v1/signing-sessions/sess_1/recipients/rec_1/verify-otp"
	if hitPath != want {
		t.Errorf("path = %s, want %s", hitPath, want)
	}
	if got["code"] != "123456" {
		t.Errorf("body code = %v, want 123456", got["code"])
	}
	if result["signingToken"] != "tok_xyz" {
		t.Errorf("signingToken = %v", result["signingToken"])
	}
}

func TestUnit_Sessions_RecipientSign(t *testing.T) {
	var hitPath string
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"status": "signed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Sessions.RecipientSign("sess_1", "rec_1", "tok_xyz")
	if err != nil {
		t.Fatal(err)
	}
	want := "/sdk/v1/signing-sessions/sess_1/recipients/rec_1/sign"
	if hitPath != want {
		t.Errorf("path = %s, want %s", hitPath, want)
	}
	if got["signingToken"] != "tok_xyz" {
		t.Errorf("body signingToken = %v, want tok_xyz", got["signingToken"])
	}
	if result["status"] != "signed" {
		t.Errorf("status = %v", result["status"])
	}
}

func TestUnit_Sessions_ValidationErrors(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	if _, err := c.Sessions.Get(""); err == nil {
		t.Error("Get: expected error for empty sessionID")
	}
	if _, err := c.Sessions.SendOTP("", "r"); err == nil {
		t.Error("SendOTP: expected error for empty sessionID")
	}
	if _, err := c.Sessions.SendOTP("s", ""); err == nil {
		t.Error("SendOTP: expected error for empty recipientID")
	}
	if _, err := c.Sessions.VerifyOTP("", "r", "c"); err == nil {
		t.Error("VerifyOTP: expected error for empty sessionID")
	}
	if _, err := c.Sessions.VerifyOTP("s", "", "c"); err == nil {
		t.Error("VerifyOTP: expected error for empty recipientID")
	}
	if _, err := c.Sessions.VerifyOTP("s", "r", ""); err == nil {
		t.Error("VerifyOTP: expected error for empty code")
	}
	if _, err := c.Sessions.RecipientSign("", "r", "t"); err == nil {
		t.Error("RecipientSign: expected error for empty sessionID")
	}
	if _, err := c.Sessions.RecipientSign("s", "", "t"); err == nil {
		t.Error("RecipientSign: expected error for empty recipientID")
	}
	if _, err := c.Sessions.RecipientSign("s", "r", ""); err == nil {
		t.Error("RecipientSign: expected error for empty signingToken")
	}
}

// ---------------------------------------------------------------------------
// 6. Certificates resource
// ---------------------------------------------------------------------------

func TestUnit_Certificates_Issue_Post(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/v1/certificates/issue" {
			t.Errorf("path = %s, want /sdk/v1/certificates/issue", r.URL.Path)
		}
		got = readBody(r)
		jsonResponse(w, 201, map[string]interface{}{"serialNumber": "SN001"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Certificates.Issue(certysign.IssueCertificateRequest{
		CommonName:   "Alice Doe",
		Organisation: "ACME Corp",
		Email:        "alice@example.com",
		Country:      "KE",
	})
	if err != nil {
		t.Fatalf("Issue() error: %v", err)
	}
	if result["serialNumber"] != "SN001" {
		t.Errorf("serialNumber = %v", result["serialNumber"])
	}
	if got["commonName"] != "Alice Doe" {
		t.Errorf("commonName = %v", got["commonName"])
	}
	// British spelling for organisation
	if got["organisation"] != "ACME Corp" {
		t.Errorf("organisation = %v, want ACME Corp (British spelling)", got["organisation"])
	}
}

func TestUnit_Certificates_Issue_Validation(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})

	_, err := c.Certificates.Issue(certysign.IssueCertificateRequest{})
	if err == nil {
		t.Error("expected error when CommonName is empty")
	}
	_, err = c.Certificates.Issue(certysign.IssueCertificateRequest{CommonName: "x"})
	if err == nil {
		t.Error("expected error when Organisation is empty")
	}
}

func TestUnit_Certificates_Verify_Get(t *testing.T) {
	var hitPath string
	var hitQuery string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		hitQuery = r.URL.RawQuery
		jsonResponse(w, 200, map[string]interface{}{"valid": true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Certificates.Verify("SN001", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/certificates/SN001/verify" {
		t.Errorf("path = %s", hitPath)
	}
	if !strings.Contains(hitQuery, "atTime=") {
		t.Errorf("query %q should contain atTime=", hitQuery)
	}
}

func TestUnit_Certificates_Status_Get(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"status": "active"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Certificates.Status("SN001")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/certificates/SN001/status" {
		t.Errorf("path = %s", hitPath)
	}
	if result["status"] != "active" {
		t.Errorf("status = %v", result["status"])
	}
}

func TestUnit_Certificates_GetActive(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"serialNumber": "SN999"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Certificates.GetActive()
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/certificates/active" {
		t.Errorf("path = %s, want /sdk/v1/certificates/active", hitPath)
	}
}

// ---------------------------------------------------------------------------
// 7. Envelopes resource
// ---------------------------------------------------------------------------

func TestUnit_Envelopes_Create_Post(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/v1/envelopes" {
			t.Errorf("path = %s, want /sdk/v1/envelopes", r.URL.Path)
		}
		got = readBody(r)
		jsonResponse(w, 201, map[string]interface{}{"id": "env_001"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Envelopes.Create(certysign.CreateEnvelopeRequest{
		Title: "Sales Contract",
		Signers: []certysign.EnvelopeSigner{
			{Email: "bob@example.com", Name: "Bob"},
		},
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if result["id"] != "env_001" {
		t.Errorf("id = %v", result["id"])
	}
	if got["title"] != "Sales Contract" {
		t.Errorf("title = %v", got["title"])
	}
}

func TestUnit_Envelopes_Create_Validation(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})
	_, err := c.Envelopes.Create(certysign.CreateEnvelopeRequest{})
	if err == nil {
		t.Error("expected error when Title is empty")
	}
}

func TestUnit_Envelopes_Get(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"id": "env_abc"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Envelopes.Get("env_abc")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes/env_abc" {
		t.Errorf("path = %s", hitPath)
	}
}

func TestUnit_Envelopes_List(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Envelopes.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes" {
		t.Errorf("path = %s", hitPath)
	}
}

func TestUnit_Envelopes_Send(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"status": "sent"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Envelopes.Send("env_001")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes/env_001/send" {
		t.Errorf("path = %s", hitPath)
	}
	if result["status"] != "sent" {
		t.Errorf("status = %v", result["status"])
	}
}

func TestUnit_Envelopes_Sign(t *testing.T) {
	var hitPath string
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"status": "signed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Envelopes.Sign("env_001", certysign.EnvelopeSignRequest{
		SignerEmail:  "bob@example.com",
		SigningToken: "tok_abc",
		Reason:       "Approval",
		Location:     "Nairobi",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes/env_001/sign" {
		t.Errorf("path = %s", hitPath)
	}
	if got["signerEmail"] != "bob@example.com" {
		t.Errorf("signerEmail = %v", got["signerEmail"])
	}
	if got["signingToken"] != "tok_abc" {
		t.Errorf("signingToken = %v", got["signingToken"])
	}
	if got["location"] != "Nairobi" {
		t.Errorf("location = %v", got["location"])
	}
}

func TestUnit_Envelopes_Sign_Defaults(t *testing.T) {
	var got map[string]interface{}
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = readBody(r)
		jsonResponse(w, 200, map[string]interface{}{"status": "signed"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Envelopes.Sign("env_001", certysign.EnvelopeSignRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got["reason"] != "Digital signature" {
		t.Errorf("reason = %v, want Digital signature", got["reason"])
	}
	if got["location"] != "Nairobi, Kenya" {
		t.Errorf("location = %v, want Nairobi, Kenya", got["location"])
	}
}

func TestUnit_Envelopes_GetDocument(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "%PDF-stub")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	data, err := c.Envelopes.GetDocument("env_001", "doc_001")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes/env_001/documents/doc_001" {
		t.Errorf("path = %s", hitPath)
	}
	if len(data) == 0 {
		t.Error("expected non-empty document bytes")
	}
}

func TestUnit_Envelopes_GetAuditTrail(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"events": []interface{}{}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Envelopes.GetAuditTrail("env_001")
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/envelopes/env_001/audit" {
		t.Errorf("path = %s, want /sdk/v1/envelopes/env_001/audit", hitPath)
	}
}

// ---------------------------------------------------------------------------
// 8. Dashboard resource
// ---------------------------------------------------------------------------

func TestUnit_Dashboard_GetStats(t *testing.T) {
	var hitPath string
	var hitQuery string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		hitQuery = r.URL.RawQuery
		jsonResponse(w, 200, map[string]interface{}{"total": 42})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.Dashboard.GetStats(map[string]string{"from": "2024-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/dashboard/stats" {
		t.Errorf("path = %s", hitPath)
	}
	if !strings.Contains(hitQuery, "from=") {
		t.Errorf("query %q should contain from=", hitQuery)
	}
	if result["total"] == nil {
		t.Error("expected total in result")
	}
}

func TestUnit_Dashboard_GetRecipients(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _ = c.Dashboard.GetRecipients(nil)
	if hitPath != "/sdk/v1/dashboard/recipients" {
		t.Errorf("path = %s, want /sdk/v1/dashboard/recipients", hitPath)
	}
}

func TestUnit_Dashboard_GetDocuments(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _ = c.Dashboard.GetDocuments(nil)
	if hitPath != "/sdk/v1/dashboard/documents" {
		t.Errorf("path = %s, want /sdk/v1/dashboard/documents", hitPath)
	}
}

// ---------------------------------------------------------------------------
// 9. PKI resource
// ---------------------------------------------------------------------------

func TestUnit_PKI_CRL(t *testing.T) {
	var hitPath string
	var hitAccept string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		hitAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	raw, err := c.PKI.CRL("")
	if err != nil {
		t.Fatalf("CRL() error: %v", err)
	}
	data, ok := raw.(string)
	if !ok {
		t.Fatalf("CRL() type = %T, want string", raw)
	}
	if hitPath != "/sdk/v1/pki/crl" {
		t.Errorf("path = %s", hitPath)
	}
	if hitAccept != "application/x-pem-file" {
		t.Errorf("accept = %q, want application/x-pem-file", hitAccept)
	}
	if len(data) == 0 {
		t.Error("expected non-empty CRL data")
	}
}

func TestUnit_PKI_OCSP(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"status": "good"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	raw, err := c.PKI.OCSP("SN001", "json")
	if err != nil {
		t.Fatal(err)
	}
	result, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("OCSP() type = %T, want map[string]interface{}", raw)
	}
	if hitPath != "/sdk/v1/pki/ocsp/SN001" {
		t.Errorf("path = %s", hitPath)
	}
	if result["status"] != "good" {
		t.Errorf("status = %v", result["status"])
	}
}

func TestUnit_PKI_OCSP_Validation(t *testing.T) {
	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: "http://localhost:1",
	})
	_, err := c.PKI.OCSP("", "json")
	if err == nil {
		t.Error("expected error for empty serialNumber")
	}
}

func TestUnit_PKI_Chain(t *testing.T) {
	var hitPath string
	var hitAccept string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		hitAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = io.WriteString(w, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	chain, err := c.PKI.Chain()
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/pki/chain" {
		t.Errorf("path = %s", hitPath)
	}
	if hitAccept != "application/x-pem-file" {
		t.Errorf("accept = %q, want application/x-pem-file", hitAccept)
	}
	if !strings.Contains(chain, "BEGIN CERTIFICATE") {
		t.Errorf("chain = %q", chain)
	}
}

func TestUnit_PKI_Info(t *testing.T) {
	var hitPath string
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		jsonResponse(w, 200, map[string]interface{}{"version": "1.0"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result, err := c.PKI.Info()
	if err != nil {
		t.Fatal(err)
	}
	if hitPath != "/sdk/v1/pki/info" {
		t.Errorf("path = %s", hitPath)
	}
	if result["version"] == nil {
		t.Error("expected version in result")
	}
}

// ---------------------------------------------------------------------------
// 10. Error handling
// ---------------------------------------------------------------------------

func TestUnit_ErrorType(t *testing.T) {
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 401, map[string]interface{}{
			"message": "Unauthorized",
			"code":    "AUTH_REQUIRED",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Dashboard.GetStats(nil)
	if err == nil {
		t.Fatal("expected error for 401 status")
	}

	var apiErr *certysign.CertySignError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *CertySignError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
	if apiErr.Code != "AUTH_REQUIRED" {
		t.Errorf("Code = %s, want AUTH_REQUIRED", apiErr.Code)
	}
}

func TestUnit_ErrorNonJSON(t *testing.T) {
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = io.WriteString(w, "internal server error")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.Dashboard.GetStats(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// 11. Retry behaviour
// ---------------------------------------------------------------------------

func TestUnit_RetryOn429(t *testing.T) {
	attempts := 0
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(429)
			return
		}
		jsonResponse(w, 200, map[string]interface{}{"ok": true})
	}))
	defer srv.Close()

	c, err := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: srv.URL,
		Retries: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = c.Dashboard.GetStats(nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
	// Retry back-off should add at least some delay (≥ 200ms for first retry)
	if elapsed < 150*time.Millisecond {
		t.Errorf("elapsed %v — expected back-off delay between retries", elapsed)
	}
}

func TestUnit_NoRetryOn4xx(t *testing.T) {
	attempts := 0
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		jsonResponse(w, 400, map[string]interface{}{"message": "bad request"})
	}))
	defer srv.Close()

	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: srv.URL,
		Retries: 3,
	})
	_, _ = c.Dashboard.GetStats(nil)
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry on 400), got %d", attempts)
	}
}

func TestUnit_RetryOn503(t *testing.T) {
	attempts := 0
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(503)
			return
		}
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c, _ := certysign.New(certysign.Config{
		PublicKey: "pk", SecretKey: "sk",
		BaseURL: srv.URL,
		Retries: 2,
	})
	_, err := c.Dashboard.GetStats(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// ---------------------------------------------------------------------------
// 12. Idempotency key uniqueness
// ---------------------------------------------------------------------------

func TestUnit_IdempotencyKeyIsUnique(t *testing.T) {
	keys := make([]string, 0, 5)
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("X-Idempotency-Key"))
		jsonResponse(w, 200, map[string]interface{}{})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	for i := 0; i < 5; i++ {
		_, _ = c.Dashboard.GetStats(nil)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Errorf("duplicate idempotency key: %s", k)
		}
		seen[k] = true
	}
}

// ---------------------------------------------------------------------------
// 13. Type-shape compile-time assertions
// ---------------------------------------------------------------------------

var _ = certysign.HashAndSignRequest{
	Document:      []byte(""),
	DocumentHash:  "",
	HashAlgorithm: "sha256",
	FileName:      "",
	Reason:        "",
	Location:      "",
	SignerName:    "",
	SignerEmail:   "",
}

var _ = certysign.BatchHashAndSignRequest{
	Documents:            []certysign.HashAndSignRequest{},
	DefaultHashAlgorithm: "sha256",
	Reason:               "",
	SignerName:           "",
	SignerEmail:          "",
	Metadata:             map[string]interface{}{},
	CertSerialNumber:     "",
}

var _ = certysign.CreateSessionRequest{
	Name:         "test",
	Documents:    []map[string]interface{}{},
	Recipients:   []map[string]interface{}{},
	SigningOrder: "parallel",
}

var _ = certysign.IssueCertificateRequest{
	CommonName:   "",
	Organisation: "",
	Country:      "",
	State:        "",
	Locality:     "",
	Email:        "",
	ValidityDays: 0,
}

var _ = certysign.CreateEnvelopeRequest{
	Title: "",
}

var _ = certysign.EnvelopeSigner{
	Email: "",
	Name:  "",
	Role:  "",
	Order: 0,
}

var _ = certysign.EnvelopeSignRequest{
	SignerEmail:  "",
	SigningToken: "",
	Reason:       "",
	Location:     "",
}

// ---------------------------------------------------------------------------
// 14. Integration tests (skipped unless API keys are provided)
// ---------------------------------------------------------------------------

func integrationClient(t *testing.T) *certysign.Client {
	t.Helper()
	pub := os.Getenv("CERTYSIGN_PUBLIC_KEY")
	sec := os.Getenv("CERTYSIGN_SECRET_KEY")
	env := os.Getenv("CERTYSIGN_ENV")
	if pub == "" || sec == "" {
		t.Skip("integration test requires CERTYSIGN_PUBLIC_KEY and CERTYSIGN_SECRET_KEY")
	}
	if env == "" {
		env = certysign.EnvironmentStaging
	}
	c, err := certysign.New(certysign.Config{
		PublicKey:   pub,
		SecretKey:   sec,
		Environment: env,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return c
}

func TestIntegration_DashboardStats(t *testing.T) {
	c := integrationClient(t)
	result, err := c.Dashboard.GetStats(nil)
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	t.Logf("GetStats result: %v", result)
}

func TestIntegration_HasherAndSign(t *testing.T) {
	c := integrationClient(t)

	data := []byte("hello integration test " + fmt.Sprintf("%d", time.Now().UnixNano()))
	hashResult, err := c.Hasher.Hash(data, "")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	t.Logf("Hash: %s (%s)", hashResult.Hash, hashResult.Algorithm)

	result, err := c.Sign.HashAndSign(certysign.HashAndSignRequest{
		Document: data,
		FileName: "integration-test.pdf",
		Reason:   "Go SDK integration test",
	})
	if err != nil {
		t.Fatalf("HashAndSign() error: %v", err)
	}
	t.Logf("HashAndSign result: %v", result)
}

func TestIntegration_PKI_Info(t *testing.T) {
	c := integrationClient(t)
	result, err := c.PKI.Info()
	if err != nil {
		t.Fatalf("PKI.Info() error: %v", err)
	}
	t.Logf("PKI.Info result: %v", result)
}

func TestIntegration_Certificates_GetActive(t *testing.T) {
	c := integrationClient(t)
	result, err := c.Certificates.GetActive()
	if err != nil {
		t.Fatalf("GetActive() error: %v", err)
	}
	t.Logf("GetActive result: %v", result)
}
