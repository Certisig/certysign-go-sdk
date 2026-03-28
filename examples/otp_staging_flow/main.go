package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	certysign "github.com/Certisig/certysign-go-sdk/certysign"
)

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		exitf("missing required environment variable: %s", name)
	}
	return value
}

func getSessionData(result map[string]interface{}) map[string]interface{} {
	data, _ := result["data"].(map[string]interface{})
	if data == nil {
		return nil
	}
	if session, ok := data["session"].(map[string]interface{}); ok {
		return session
	}
	return data
}

func markerFlags(pdfBytes []byte, signerEmail string) map[string]bool {
	return map[string]bool{
		"byteRange":   strings.Contains(string(pdfBytes), "/ByteRange"),
		"sigField":    strings.Contains(string(pdfBytes), "/FT /Sig"),
		"widget":      strings.Contains(string(pdfBytes), "/Subtype /Widget"),
		"signerEmail": strings.Contains(string(pdfBytes), signerEmail),
	}
}

func main() {
	publicKey := requireEnv("CERTYSIGN_PUBLIC_KEY")
	secretKey := requireEnv("CERTYSIGN_SECRET_KEY")
	environment := os.Getenv("CERTYSIGN_ENVIRONMENT")
	if environment == "" {
		environment = "staging"
	}
	signerEmail := requireEnv("TEST_SIGNER_EMAIL")

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		exitf("failed to resolve source path")
	}
	rootDir, err := filepath.Abs(filepath.Join(filepath.Dir(sourceFile), "../../.."))
	if err != nil {
		exitErr(err)
	}

	pdfPath := filepath.Join(rootDir, "CV_Jotham_Mwangi.pdf")
	if len(os.Args) > 1 {
		pdfPath, err = filepath.Abs(os.Args[1])
		if err != nil {
			exitErr(err)
		}
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		exitErr(err)
	}

	client, err := certysign.New(certysign.Config{
		PublicKey:   publicKey,
		SecretKey:   secretKey,
		Environment: environment,
	})
	if err != nil {
		exitErr(err)
	}

	hashResult, err := client.Hasher.HashFile(pdfPath, "sha256")
	if err != nil {
		exitErr(err)
	}

	createResult, err := client.Sessions.Create(certysign.CreateSessionRequest{
		Name: fmt.Sprintf("OTP parity check go %s", time.Now().UTC().Format(time.RFC3339Nano)),
		Documents: []map[string]interface{}{
			{
				"documentId":    fmt.Sprintf("go-%d", time.Now().Unix()),
				"fileName":      filepath.Base(pdfPath),
				"hash":          hashResult.Hash,
				"hashAlgorithm": hashResult.Algorithm,
				"mimeType":      "application/pdf",
			},
		},
		Recipients: []map[string]interface{}{
			{
				"email": signerEmail,
				"name":  signerEmail,
				"role":  "signer",
				"order": 1,
			},
		},
		SigningOrder: "parallel",
	})
	if err != nil {
		exitErr(err)
	}

	sessionData := getSessionData(createResult)
	if sessionData == nil {
		exitf("unexpected session response: no session payload")
	}
	sessionID, _ := sessionData["_id"].(string)
	recipients, _ := sessionData["recipients"].([]interface{})
	if sessionID == "" || len(recipients) == 0 {
		printJSON(map[string]interface{}{
			"message": "unexpected session response",
			"result":  createResult,
		})
		os.Exit(1)
	}
	firstRecipient, _ := recipients[0].(map[string]interface{})
	recipientID, _ := firstRecipient["recipientId"].(string)
	if recipientID == "" {
		printJSON(map[string]interface{}{
			"message": "missing recipientId in session response",
			"result":  createResult,
		})
		os.Exit(1)
	}

	sendOTPResult, err := client.Sessions.SendOTP(sessionID, recipientID)
	if err != nil {
		exitErr(err)
	}

	printJSON(map[string]interface{}{
		"language":    "go",
		"step":        "otp_sent",
		"pdfPath":     pdfPath,
		"environment": environment,
		"sessionId":   sessionID,
		"recipientId": recipientID,
		"email":       signerEmail,
		"sendOtp":     sendOTPResult,
	})

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter OTP for Go session %s: ", sessionID)
	code, err := reader.ReadString('\n')
	if err != nil {
		exitErr(err)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		exitf("OTP code is required")
	}

	verifyResult, err := client.Sessions.VerifyOTP(sessionID, recipientID, code)
	if err != nil {
		exitErr(err)
	}
	verifyData, _ := verifyResult["data"].(map[string]interface{})
	signingToken, _ := verifyData["signingToken"].(string)
	if signingToken == "" {
		printJSON(map[string]interface{}{
			"message": "missing signingToken in verify response",
			"result":  verifyResult,
		})
		os.Exit(1)
	}

	signResult, err := client.Sessions.RecipientSign(sessionID, recipientID, signingToken)
	if err != nil {
		exitErr(err)
	}
	signData, _ := signResult["data"].(map[string]interface{})
	if signData == nil {
		exitf("missing data in sign response")
	}
	signedDocuments, _ := signData["signedDocuments"].([]interface{})
	if len(signedDocuments) == 0 {
		printJSON(map[string]interface{}{
			"message": "missing signedDocuments in sign response",
			"result":  signResult,
		})
		os.Exit(1)
	}
	firstSigned, _ := signedDocuments[0].(map[string]interface{})
	signature, _ := firstSigned["signature"].(string)
	if signature == "" {
		printJSON(map[string]interface{}{
			"message": "missing signature in signedDocuments",
			"result":  signResult,
		})
		os.Exit(1)
	}

	certificate, _ := signData["certificate"].(string)
	chain, _ := signData["chain"].(string)
	certSerialNumber, _ := signData["certSerialNumber"].(string)

	signedPDF, err := client.Embedder.EmbedInPDF(pdfBytes, certysign.EmbedInPDFOptions{
		Signature:        signature,
		Certificate:      certificate,
		Chain:            chain,
		CertSerialNumber: certSerialNumber,
		SignerEmail:      signerEmail,
		Reason:           "OTP staging parity test",
	})
	if err != nil {
		exitErr(err)
	}

	outputDir := filepath.Join(rootDir, "otp_staging_runs", "output")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		exitErr(err)
	}
	outputPath := filepath.Join(outputDir, "go-otp-signed.pdf")
	reportPath := filepath.Join(outputDir, "go-otp-report.json")
	if err := os.WriteFile(outputPath, signedPDF, 0o644); err != nil {
		exitErr(err)
	}

	report := map[string]interface{}{
		"language":        "go",
		"environment":     environment,
		"pdfPath":         pdfPath,
		"outputPath":      outputPath,
		"sessionId":       sessionID,
		"recipientId":     recipientID,
		"documentHash":    hashResult.Hash,
		"hashAlgorithm":   hashResult.Algorithm,
		"verifyExpiresAt": verifyData["expiresAt"],
		"signResponseKeys": func() []string {
			keys := make([]string, 0, len(signData))
			for key := range signData {
				keys = append(keys, key)
			}
			return keys
		}(),
		"markers": markerFlags(signedPDF, signerEmail),
	}
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		exitErr(err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		exitErr(err)
	}
	fmt.Println(string(reportBytes))
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func exitErr(err error) {
	exitf("%v", err)
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
