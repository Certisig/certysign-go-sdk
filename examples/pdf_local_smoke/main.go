package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	certysign "github.com/Certisig/certysign-go-sdk/certysign"
)

type smokeResult struct {
	Language     string          `json:"language"`
	FileName     string          `json:"fileName"`
	DocumentHash string          `json:"documentHash"`
	Algorithm    string          `json:"algorithm"`
	OutputPath   string          `json:"outputPath"`
	OutputSize   int             `json:"outputSize"`
	SignedSHA256 string          `json:"signedSha256"`
	Markers      map[string]bool `json:"markers"`
}

func main() {
	if len(os.Args) != 6 {
		exitf("usage: go run ./examples/pdf_local_smoke/main.go <pdf> <cert.pem> <key.pem> <cert-serial> <output.pdf>")
	}

	pdfPath := os.Args[1]
	certPath := os.Args[2]
	keyPath := os.Args[3]
	certSerial := os.Args[4]
	outputPath := os.Args[5]

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		exitErr(err)
	}
	certPEMBytes, err := os.ReadFile(certPath)
	if err != nil {
		exitErr(err)
	}
	privateKey, err := loadPrivateKey(keyPath)
	if err != nil {
		exitErr(err)
	}

	client, err := certysign.New(certysign.Config{
		PublicKey:   "local-test",
		SecretKey:   "local-test",
		Environment: certysign.EnvironmentTest,
		TSAUrl:      "disabled",
	})
	if err != nil {
		exitErr(err)
	}

	hashResult, err := client.Hasher.HashFile(pdfPath, "")
	if err != nil {
		exitErr(err)
	}

	signedPDF, err := client.Embedder.EmbedInPDF(pdfBytes, certysign.EmbedInPDFOptions{
		SignerEmail: "qa@example.com",
		Reason:      "Local SDK smoke test",
		Location:    "Nairobi",
		Timestamp:   "2026-03-20T12:00:00Z",
		Standard:    "PAdES Baseline B-B",
		TSAUrl:      "disabled",
		SignCallback: func(hashHex string) (map[string]interface{}, error) {
			digest, err := hex.DecodeString(hashHex)
			if err != nil {
				return nil, err
			}
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"data": map[string]interface{}{
					"signature":   base64.StdEncoding.EncodeToString(signature),
					"certificate": string(certPEMBytes),
					"certSerialNumber": certSerial,
				},
			}, nil
		},
	})
	if err != nil {
		exitErr(err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		exitErr(err)
	}
	if err := os.WriteFile(outputPath, signedPDF, 0o644); err != nil {
		exitErr(err)
	}

	signedHash := sha256.Sum256(signedPDF)
	result := smokeResult{
		Language:     "go",
		FileName:     filepath.Base(pdfPath),
		DocumentHash: hashResult.Hash,
		Algorithm:    hashResult.Algorithm,
		OutputPath:   outputPath,
		OutputSize:   len(signedPDF),
		SignedSHA256: hex.EncodeToString(signedHash[:]),
		Markers: map[string]bool{
			"byteRange":   bytes.Contains(signedPDF, []byte("/ByteRange")),
			"sigField":    bytes.Contains(signedPDF, []byte("/FT /Sig")),
			"widget":      bytes.Contains(signedPDF, []byte("/Subtype /Widget")),
			"signerEmail": bytes.Contains(signedPDF, []byte("qa@example.com")),
		},
	}

	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		exitErr(err)
	}
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode private key PEM: no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want *rsa.PrivateKey", keyAny)
	}
	return key, nil
}

func exitErr(err error) {
	exitf("%v", err)
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
