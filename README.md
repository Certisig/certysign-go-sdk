# CertySign SDK — Go

[![Go Reference](https://pkg.go.dev/badge/github.com/certysign/sdk-go.svg)](https://pkg.go.dev/github.com/certysign/sdk-go)
[![Go 1.21+](https://img.shields.io/badge/go-1.21+-blue.svg)](https://go.dev)

Official Go SDK for the [CertySign Trust Services](https://certysign.io) platform. Mirrors the `@certysign/sdk` Node.js package feature-for-feature.

> **Privacy-first**: Your documents never leave your infrastructure. Only cryptographic hashes are transmitted to the API.

---

## Installation

```bash
go get github.com/certysign/sdk-go
```

---

## Quick start

```go
package main

import (
    "fmt"
    "log"
    "github.com/certysign/sdk-go/certysign"
)

func main() {
    client, err := certysign.New(certysign.Config{
        PublicKey: "YOUR_API_KEY_ID",
        SecretKey: "YOUR_API_KEY_SECRET",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Optional: check that the configured key can reach the API
    fmt.Println(client.Ping()["success"])
    _ = client
}
```

---

## Core workflows

### 1 — Hash-based signing (recommended)

```go
// Hash the document locally — it never leaves your server
data, err := os.ReadFile("invoice.pdf")
if err != nil {
    log.Fatal(err)
}

// Hash and sign from raw document bytes
result, err := client.Sign.HashAndSign(certysign.HashAndSignRequest{
    Document: data,
    FileName: "invoice.pdf",
    Reason:   "Invoice approval",
})
```

If you already computed the hash yourself, use `SignHash()` instead:

```go
hashResult, err := client.Hasher.HashFile("invoice.pdf", "")
if err != nil {
    log.Fatal(err)
}

result, err := client.Sign.SignHash(certysign.HashAndSignRequest{
    DocumentHash:  hashResult.Hash,
    HashAlgorithm: hashResult.Algorithm,
    FileName:      "invoice.pdf",
})
```

### 2 — Local PDF signature embedding (PAdES)

```go
pdfBytes, _ := os.ReadFile("invoice.pdf")

signedPDF, err := client.Embedder.EmbedInPDF(pdfBytes, certysign.EmbedInPDFOptions{
    Reason:      "Invoice approval",
    SignerEmail: "alice@example.com",
    SignCallback: func(hashHex string) (map[string]interface{}, error) {
        return client.Sign.SignHash(certysign.HashAndSignRequest{
            DocumentHash:  hashHex,
            HashAlgorithm: "sha256",
        })
    },
})
if err != nil {
    log.Fatal(err)
}
os.WriteFile("invoice-signed.pdf", signedPDF, 0644)
```

### 3 — PAdES B-T (with RFC 3161 timestamp)

```go
client, _ := certysign.New(certysign.Config{
    PublicKey: "...",
    SecretKey: "...",
    TSAUrl:    "https://tsa.certysign.io", // upgrades to PAdES B-T automatically
})
```

### 4 — XML signing (XMLDSig enveloped)

```go
xmlBytes, _ := os.ReadFile("document.xml")

hash, _ := client.Hasher.Hash(xmlBytes, "sha256")
signResult, _ := client.Sign.SignHash(certysign.HashAndSignRequest{
    DocumentHash:  hash.Hash,
    HashAlgorithm: hash.Algorithm,
})

sig := signResult["data"].(map[string]interface{})["signature"].(string)
cert := signResult["data"].(map[string]interface{})["certificate"].(string)

signedXML, err := client.Embedder.EmbedInXML(string(xmlBytes), certysign.EmbedInXMLOptions{
    Signature:    sig,
    Certificate:  cert,
    DocumentHash: hash.Hash,
})
```

### 5 — JSON signing

```go
payload := map[string]interface{}{"amount": 1500, "currency": "USD"}
payloadBytes, _ := json.Marshal(payload)

hash, _ := client.Hasher.Hash(payloadBytes, "sha256")
signResult, _ := client.Sign.SignHash(certysign.HashAndSignRequest{
    DocumentHash: hash.Hash,
})

sig := signResult["data"].(map[string]interface{})["signature"].(string)

signedEnvelope, _ := client.Embedder.EmbedInJSON(payload, certysign.EmbedInJSONOptions{
    Signature: sig,
})
```

### 6 — Signature envelope workflow (multi-recipient)

```go
// Create envelope
envelope, _ := client.Envelopes.Create(certysign.CreateEnvelopeRequest{
    Title: "Service Agreement",
    Signers: []certysign.EnvelopeSigner{
        {Email: "alice@example.com", Name: "Alice"},
        {Email: "bob@example.com",   Name: "Bob"},
    },
})

envelopeID := envelope["data"].(map[string]interface{})["id"].(string)

// Upload documents
docBytes, _ := os.ReadFile("agreement.pdf")
client.Envelopes.UploadDocuments(envelopeID, []certysign.EnvelopeDocument{
    {Name: "agreement.pdf", Data: docBytes},
})

// Send to signers
client.Envelopes.Send(envelopeID)
```

### 7 — Signing sessions (OTP)

```go
hashResult, _ := client.Hasher.HashFile("agreement.pdf", "sha256")

session, _ := client.Sessions.Create(certysign.CreateSessionRequest{
    Name: "Q1 Board Resolution",
    Documents: []map[string]interface{}{
        {
            "documentId":    "doc-resolution",
            "fileName":      "agreement.pdf",
            "hash":          hashResult.Hash,
            "hashAlgorithm": hashResult.Algorithm,
            "mimeType":      "application/pdf",
        },
    },
    Recipients: []map[string]interface{}{
        {"email": "alice@example.com", "name": "Alice", "role": "signer", "order": 1},
    },
    SigningOrder: "parallel",
})
data := session["data"].(map[string]interface{})
sessionData := data["session"].(map[string]interface{})
sessionID := sessionData["_id"].(string)
recipientID := sessionData["recipients"].([]interface{})[0].(map[string]interface{})["recipientId"].(string)

// Send OTP
client.Sessions.SendOTP(sessionID, recipientID)

// Verify OTP and sign
verifyResult, _ := client.Sessions.VerifyOTP(sessionID, recipientID, "123456")
signingToken := verifyResult["data"].(map[string]interface{})["signingToken"].(string)
client.Sessions.RecipientSign(sessionID, recipientID, signingToken)
```

---

## API Reference

### `certysign.New(cfg Config) (*Client, error)`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `PublicKey` | string | *required* | `X-API-Key-Id` header |
| `SecretKey` | string | *required* | `X-API-Key-Secret` header |
| `Environment` | string | `"production"` | `"production"` \| `"staging"` \| `"development"` \| `"test"` |
| `BaseURL` | string | | Override API base URL |
| `Timeout` | int | `30` | HTTP timeout in seconds |
| `Retries` | int | `3` | Max retries for transient failures |
| `Debug` | bool | `false` | Verbose request logging |
| `TSAUrl` | string | | TSA service URL for PAdES-T timestamps |

### Client resources

| Field | Type | Description |
|-------|------|-------------|
| `client.Sign` | `*HashSigningResource` | Hash-based signing (recommended) |
| `client.Certificates` | `*CertificateResource` | Certificate lifecycle |
| `client.PKI` | `*PKIResource` | CRL, OCSP, chain, info |
| `client.Envelopes` | `*EnvelopeResource` | Signature envelopes |
| `client.Sessions` | `*SigningSessionResource` | OTP-verified signing sessions |
| `client.Dashboard` | `*DashboardResource` | Analytics |
| `client.Hasher` | `*DocumentHasher` | Local hashing (no network) |
| `client.Embedder` | `*SignatureEmbedder` | Local signature embedding (no network) |
| `client.LegacySign` | `*SigningResource` | Legacy upload-based signing |

---

## Error handling

```go
result, err := client.Sign.HashAndSign(certysign.HashAndSignRequest{...})
if err != nil {
    if csErr, ok := err.(*certysign.CertySignError); ok {
        log.Printf("API error %d [%s]: %s", csErr.StatusCode, csErr.Code, csErr.Message)
    } else {
        log.Printf("Network error: %v", err)
    }
}
```

---

## Environments

| `Environment` | Base URL |
|---------------|----------|
| `"production"` | `https://core.certysign.io` |
| `"staging"` | `https://service.certysign.io` |
| `"development"` | `http://localhost:8000` |
| `"test"` | `http://localhost:8000` |

---

## License

MIT © CertySign Trust Services
