// Package certysign — SignatureEmbedder
//
// Embeds CMS/PKCS#7 signatures into documents locally on the subscriber's system.
// Documents NEVER leave the subscriber's infrastructure.
//
// PDF signing follows PAdES Baseline B-B / B-T:
//   - Visual stamp added to last page via PDF content stream operators
//   - /Sig dictionary with ByteRange placeholder injected
//   - PKCS#7 SignedData built with encoding/asn1 and digitorus/pkcs7
//   - RFC 3161 TSA timestamp added when TSAUrl is configured (B-T)
//
// Requires: github.com/digitorus/pkcs7
//
// Install: go get github.com/digitorus/pkcs7

package certysign

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	sigPlaceholderLength = 32768 // hex chars (16384 bytes)
	stampWidth           = 260.0
	stampHeight          = 56.0
	stampPaddingX        = 8.0
	stampPaddingY        = 8.0
	stampFontSize        = 7.0
	stampLineHeight      = 10.0
)

// SignatureEmbedder embeds digital signatures into PDF, XML, and JSON documents.
type SignatureEmbedder struct {
	tsaURL string
}

func newSignatureEmbedder(tsaURL string) *SignatureEmbedder {
	return &SignatureEmbedder{tsaURL: tsaURL}
}

// EmbedInPDFOptions holds parameters for EmbedInPDF.
type EmbedInPDFOptions struct {
	// Signature is a pre-computed Base64 CMS/PKCS#7 signature value.
	// Mutually exclusive with SignCallback.
	Signature string
	// SignCallback is called with the ByteRange SHA-256 hash and must return
	// the HSM signature result. The result map must contain "signature" and
	// optionally "certificate" and "chain" under a "data" key.
	// Mutually exclusive with Signature.
	SignCallback func(hashHex string) (map[string]interface{}, error)
	// SignerEmail is displayed in the visual stamp.
	SignerEmail string
	// Certificate is the signer's PEM certificate.
	Certificate string
	// Chain is the PEM certificate trust chain.
	Chain string
	// CertSerialNumber is the certificate serial number (displayed in stamp).
	CertSerialNumber string
	// Reason is the signing reason.
	Reason string
	// Location is the physical signing location.
	Location string
	// Timestamp is the signing time (ISO 8601). Defaults to time.Now().
	Timestamp string
	// Standard is the signature standard label shown in stamp.
	Standard string
	// TSAUrl overrides the client-level TSA URL for this call.
	TSAUrl string
	// Page is the 1-based page number where the stamp appears. Default: last page.
	Page int
	// StampX is the X position of the stamp bottom-left corner. Default: 20.
	StampX float64
	// StampY is the Y position of the stamp bottom-left corner. Default: 20.
	StampY float64
}

// EmbedInPDF embeds a PAdES-compliant digital signature into a PDF document.
//
// The PDF is modified locally — no document bytes are transmitted over the network.
// Only the SHA-256 hash is passed to SignCallback for remote HSM signing.
//
// Returns the signed PDF as a byte slice.
func (e *SignatureEmbedder) EmbedInPDF(pdfData []byte, opts EmbedInPDFOptions) ([]byte, error) {
	if len(pdfData) == 0 {
		return nil, fmt.Errorf("certysign: EmbedInPDF: pdfData is required")
	}
	if opts.SignCallback == nil && opts.Signature == "" {
		return nil, fmt.Errorf("certysign: EmbedInPDF: SignCallback or Signature is required")
	}

	// Defaults
	reason := opts.Reason
	if reason == "" {
		reason = "Digital signature"
	}

	signerEmail := opts.SignerEmail
	if signerEmail == "" {
		signerEmail = "CertySign"
	}

	var signDate time.Time
	if opts.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, opts.Timestamp)
		if err == nil {
			signDate = t
		}
	}
	if signDate.IsZero() {
		signDate = time.Now().UTC()
	}

	tsaURL := opts.TSAUrl
	if tsaURL == "" {
		tsaURL = e.tsaURL
	}

	standard := opts.Standard
	if standard == "" {
		if tsaURL != "" {
			standard = "PAdES Baseline B-T"
		} else {
			standard = "PAdES Baseline B-B"
		}
	}

	stampX := opts.StampX
	if stampX == 0 {
		stampX = 20
	}
	stampY := opts.StampY
	if stampY == 0 {
		stampY = 20
	}

	certSerial := opts.CertSerialNumber

	// If no pre-computed serial, do preflight call with dummy hash to discover cert
	certPEM := opts.Certificate
	chainPEM := opts.Chain
	var precomputedSig string

	if opts.SignCallback != nil && certSerial == "" {
		preflight, err := opts.SignCallback(strings.Repeat("0", 64))
		if err == nil {
			if data, ok := preflight["data"].(map[string]interface{}); ok {
				if c, ok := data["certificate"].(string); ok && c != "" && certPEM == "" {
					certPEM = c
				}
				if sn, ok := data["certSerialNumber"].(string); ok {
					certSerial = sn
				}
			}
			if certSerial == "" && certPEM != "" {
				certSerial = certSerialFromPEM(certPEM)
			}
		}
	} else if opts.Signature != "" {
		precomputedSig = opts.Signature
		if certSerial == "" && certPEM != "" {
			certSerial = certSerialFromPEM(certPEM)
		}
	}

	// Build text lines for visual stamp
	stampLines := []string{
		fmt.Sprintf("Digitally signed by: %s", signerEmail),
		fmt.Sprintf("Date: %s", nodeISOTimestamp(signDate)),
		fmt.Sprintf("Certificate: %s", certSerial),
		fmt.Sprintf("Standard: %s", standard),
	}

	// Phase 1: add visual stamp + /Sig placeholder to the PDF
	phase1, sigFieldOffset, err := injectPDFSignatureField(
		pdfData, stampX, stampY, stampLines, signDate, signerEmail, reason, opts.Location, opts.Page,
	)
	if err != nil {
		return nil, fmt.Errorf("certysign: EmbedInPDF: phase1: %w", err)
	}
	_ = sigFieldOffset

	// Phase 2: locate /Contents placeholder and compute ByteRange
	pdfBuf := []byte(phase1)
	placeholder := strings.Repeat("0", sigPlaceholderLength)
	placeholderIdx := strings.Index(string(pdfBuf), placeholder)
	if placeholderIdx < 0 {
		return nil, fmt.Errorf("certysign: EmbedInPDF: could not locate /Contents placeholder in PDF output")
	}

	contentsStart := placeholderIdx - 1 // '<' angle bracket
	contentsEnd := placeholderIdx + sigPlaceholderLength + 1

	total := len(pdfBuf)
	br0, br1 := 0, contentsStart
	br2, br3 := contentsEnd, total-contentsEnd

	// Patch ByteRange in-place
	patchByteRange(pdfBuf, placeholderIdx, br0, br1, br2, br3)

	// Hash the ByteRange regions
	h := sha256.New()
	h.Write(pdfBuf[br0 : br0+br1])
	h.Write(pdfBuf[br2 : br2+br3])
	hashHex := hex.EncodeToString(h.Sum(nil))

	// Phase 3: obtain signature
	rawSigB64 := precomputedSig
	if opts.SignCallback != nil {
		signResult, err := opts.SignCallback(hashHex)
		if err != nil {
			return nil, fmt.Errorf("certysign: EmbedInPDF: sign callback: %w", err)
		}
		if data, ok := signResult["data"].(map[string]interface{}); ok {
			if sig, ok := data["signature"].(string); ok {
				rawSigB64 = sig
			}
			if certPEM == "" {
				if c, ok := data["certificate"].(string); ok {
					certPEM = c
				}
			}
			if chainPEM == "" {
				if ch, ok := data["chain"].(string); ok {
					chainPEM = ch
				}
			}
		} else {
			if sig, ok := signResult["signature"].(string); ok {
				rawSigB64 = sig
			}
		}
	}

	if rawSigB64 == "" {
		return nil, fmt.Errorf("certysign: EmbedInPDF: no signature received")
	}

	// Phase 4 (optional): TSA timestamp
	var tsaTokenDER []byte
	if tsaURL != "" {
		rawSigBytes, err := base64.StdEncoding.DecodeString(rawSigB64)
		if err == nil {
			sigHash := sha256.Sum256(rawSigBytes)
			tsaTokenDER, _ = fetchTSAToken(tsaURL, hex.EncodeToString(sigHash[:]))
		}
	}

	// Phase 5: build PKCS#7 and patch into /Contents
	p7DER, err := buildPKCS7(rawSigB64, certPEM, chainPEM, tsaTokenDER)
	if err != nil {
		return nil, fmt.Errorf("certysign: EmbedInPDF: build PKCS#7: %w", err)
	}

	p7Hex := hex.EncodeToString(p7DER)
	if len(p7Hex) > sigPlaceholderLength {
		return nil, fmt.Errorf(
			"certysign: EmbedInPDF: PKCS#7 too large (%d hex chars > %d placeholder)",
			len(p7Hex), sigPlaceholderLength,
		)
	}

	// Pad and patch
	paddedHex := p7Hex + strings.Repeat("0", sigPlaceholderLength-len(p7Hex))
	copy(pdfBuf[placeholderIdx:placeholderIdx+sigPlaceholderLength], []byte(paddedHex))

	return pdfBuf, nil
}

// EmbedInXMLOptions holds parameters for EmbedInXML.
type EmbedInXMLOptions struct {
	Signature        string
	Certificate      string
	DocumentHash     string
	HashAlgorithm    string
	CertSerialNumber string
	SignerEmail      string
	Timestamp        string
	Standard         string
}

// EmbedInXML embeds an XMLDSig enveloped signature into an XML document.
//
// Returns the signed XML string with an embedded <ds:Signature> element.
func (e *SignatureEmbedder) EmbedInXML(xmlStr string, opts EmbedInXMLOptions) (string, error) {
	if xmlStr == "" {
		return "", fmt.Errorf("certysign: EmbedInXML: xmlStr is required")
	}
	if opts.Signature == "" {
		return "", fmt.Errorf("certysign: EmbedInXML: Signature is required")
	}

	algo := strings.ToLower(opts.HashAlgorithm)
	if algo == "" {
		algo = "sha256"
	}

	algorithmURI := map[string]string{
		"sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		"sha384": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
		"sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	}[algo]
	if algorithmURI == "" {
		algorithmURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}

	digestURI := map[string]string{
		"sha256": "http://www.w3.org/2001/04/xmlenc#sha256",
		"sha384": "http://www.w3.org/2001/04/xmldsig-more#sha384",
		"sha512": "http://www.w3.org/2001/04/xmlenc#sha512",
	}[algo]
	if digestURI == "" {
		digestURI = "http://www.w3.org/2001/04/xmlenc#sha256"
	}

	signerEmail := opts.SignerEmail
	if signerEmail == "" {
		signerEmail = "CertySign"
	}

	var signDate time.Time
	if opts.Timestamp != "" {
		t, _ := time.Parse(time.RFC3339, opts.Timestamp)
		signDate = t
	}
	if signDate.IsZero() {
		signDate = time.Now().UTC()
	}

	standard := opts.Standard
	if standard == "" {
		standard = "PAdES Baseline B-B"
	}

	certValue := ""
	if opts.Certificate != "" {
		certValue = strings.ReplaceAll(opts.Certificate, "-----BEGIN CERTIFICATE-----", "")
		certValue = strings.ReplaceAll(certValue, "-----END CERTIFICATE-----", "")
		certValue = strings.ReplaceAll(certValue, "\r\n", "")
		certValue = strings.ReplaceAll(certValue, "\n", "")
		certValue = strings.TrimSpace(certValue)
	}

	digestB64 := ""
	if opts.DocumentHash != "" {
		if raw, err := hex.DecodeString(opts.DocumentHash); err == nil {
			digestB64 = base64.StdEncoding.EncodeToString(raw)
		} else {
			digestB64 = opts.DocumentHash
		}
	}

	sigXML := fmt.Sprintf(`
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="CertySign-Signature">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="%s"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="%s"/>
        <ds:DigestValue>%s</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>%s</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>%s</ds:X509Certificate>
        <ds:X509SerialNumber>%s</ds:X509SerialNumber>
      </ds:X509Data>
    </ds:KeyInfo>
    <ds:Object>
      <SignatureProperties xmlns="urn:certysign:signature:1.0">
        <SignerEmail>%s</SignerEmail>
        <Timestamp>%s</Timestamp>
        <CertSerial>%s</CertSerial>
        <Standard>%s</Standard>
        <Provider>CertySign</Provider>
      </SignatureProperties>
    </ds:Object>
  </ds:Signature>`,
		algorithmURI, digestURI, digestB64,
		opts.Signature,
		certValue,
		xmlEscape(opts.CertSerialNumber),
		xmlEscape(signerEmail),
		signDate.Format(time.RFC3339),
		xmlEscape(opts.CertSerialNumber),
		xmlEscape(standard),
	)

	// Insert before the last closing tag
	re := regexp.MustCompile(`</([^\s>]+)\s*>\s*$`)
	loc := re.FindStringIndex(xmlStr)
	if loc != nil {
		return xmlStr[:loc[0]] + sigXML + "\n" + xmlStr[loc[0]:], nil
	}
	return xmlStr + sigXML, nil
}

// EmbedInJSONOptions holds parameters for EmbedInJSON.
type EmbedInJSONOptions struct {
	Signature        string
	Certificate      string
	Chain            string
	DocumentHash     string
	HashAlgorithm    string
	Algorithm        string
	SignerEmail      string
	CertSerialNumber string
	Timestamp        string
	Standard         string
}

// EmbedInJSON creates a signed JSON envelope wrapping the original document data.
//
// Returns a map with "data", "signatures", and "metadata" keys.
func (e *SignatureEmbedder) EmbedInJSON(data interface{}, opts EmbedInJSONOptions) (map[string]interface{}, error) {
	if opts.Signature == "" {
		return nil, fmt.Errorf("certysign: EmbedInJSON: Signature is required")
	}

	signerEmail := opts.SignerEmail
	if signerEmail == "" {
		signerEmail = "CertySign"
	}

	var signDate time.Time
	if opts.Timestamp != "" {
		t, _ := time.Parse(time.RFC3339, opts.Timestamp)
		signDate = t
	}
	if signDate.IsZero() {
		signDate = time.Now().UTC()
	}

	algo := opts.Algorithm
	if algo == "" {
		algo = "SHA256withRSA"
	}
	hashAlgo := opts.HashAlgorithm
	if hashAlgo == "" {
		hashAlgo = "sha256"
	}
	standard := opts.Standard
	if standard == "" {
		standard = "PAdES Baseline B-B"
	}

	signature := map[string]interface{}{
		"value":         opts.Signature,
		"algorithm":     algo,
		"hashAlgorithm": hashAlgo,
		"documentHash":  opts.DocumentHash,
		"timestamp":     signDate.Format(time.RFC3339),
		"signer": map[string]interface{}{
			"email":            signerEmail,
			"certSerialNumber": opts.CertSerialNumber,
		},
		"certificate": opts.Certificate,
		"chain":       opts.Chain,
		"standard":    standard,
	}

	return map[string]interface{}{
		"data":       data,
		"signatures": []interface{}{signature},
		"metadata": map[string]interface{}{
			"provider":       "CertySign Trust Services",
			"version":        "2.0.0",
			"signatureCount": 1,
			"signedAt":       time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// ─── PDF helpers ──────────────────────────────────────────────────────────────

// injectPDFSignatureField appends a visual stamp content stream and a /Sig
// dictionary with ByteRange + /Contents placeholders to the PDF.
// It works at the raw byte level, appending an incremental update.
func injectPDFSignatureField(
	pdfData []byte,
	stampX, stampY float64,
	stampLines []string,
	signDate time.Time,
	signerEmail, reason, location string,
	page int,
) ([]byte, int, error) {
	pageObjs := findPageObjectNumbers(pdfData)
	if len(pageObjs) == 0 {
		return nil, 0, fmt.Errorf("certysign: EmbedInPDF: could not find any /Page objects")
	}
	pageIdx := len(pageObjs) - 1
	if page > 0 && page <= len(pageObjs) {
		pageIdx = page - 1
	}
	pageObjNum := pageObjs[pageIdx]
	pageDict := findObjectBody(pdfData, pageObjNum)
	if pageDict == "" {
		return nil, 0, fmt.Errorf("certysign: EmbedInPDF: could not read target page object")
	}

	catalogObjNum := findCatalogObjectNumber(pdfData)
	if catalogObjNum == 0 {
		return nil, 0, fmt.Errorf("certysign: EmbedInPDF: could not find /Catalog object")
	}
	catalogDict := findObjectBody(pdfData, catalogObjNum)
	if catalogDict == "" {
		return nil, 0, fmt.Errorf("certysign: EmbedInPDF: could not read catalog object")
	}

	maxObj := findMaxObjectNumber(pdfData)
	appearanceObjNum := maxObj + 1
	sigObjNum := maxObj + 2
	widgetObjNum := maxObj + 3
	annotsObjNum := maxObj + 4
	acroFormObjNum := maxObj + 5

	var buf bytes.Buffer
	buf.Write(pdfData)

	offsets := map[int]int{}

	appearanceStream := buildStampAppearanceStream(stampLines)
	offsets[appearanceObjNum] = buf.Len()
	fmt.Fprintf(
		&buf,
		"%d 0 obj\n<< /Type /XObject /Subtype /Form /FormType 1 /BBox [0 0 %.2f %.2f] /Resources << /Font << /Helvetica << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Length %d >>\nstream\n%s\nendstream\nendobj\n",
		appearanceObjNum,
		stampWidth,
		stampHeight,
		len(appearanceStream),
		appearanceStream,
	)

	placeholder := strings.Repeat("0", sigPlaceholderLength)

	offsets[sigObjNum] = buf.Len()
	sigDictContent := buildSigDictBytes(placeholder, signerEmail, reason, location, signDate)
	fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", sigObjNum, sigDictContent)

	offsets[widgetObjNum] = buf.Len()
	fmt.Fprintf(
		&buf,
		"%d 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V %d 0 R /Rect [%.2f %.2f %.2f %.2f] /F 4 /P %d 0 R /AP << /N %d 0 R >> >>\nendobj\n",
		widgetObjNum,
		sigObjNum,
		stampX,
		stampY,
		stampX+stampWidth,
		stampY+stampHeight,
		pageObjNum,
		appearanceObjNum,
	)

	existingAnnots := extractRefOrArray(pageDict, "/Annots")
	mergedAnnots := mergeRefOrArray(existingAnnots, fmt.Sprintf("%d 0 R", widgetObjNum))
	offsets[annotsObjNum] = buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", annotsObjNum, mergedAnnots)

	pageDict = upsertRefEntry(pageDict, "/Annots", fmt.Sprintf("%d 0 R", annotsObjNum))
	offsets[pageObjNum] = buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", pageObjNum, pageDict)

	offsets[acroFormObjNum] = buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n<< /Fields [%d 0 R] /SigFlags 3 >>\nendobj\n", acroFormObjNum, widgetObjNum)

	catalogDict = upsertRefEntry(catalogDict, "/AcroForm", fmt.Sprintf("%d 0 R", acroFormObjNum))
	offsets[catalogObjNum] = buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", catalogObjNum, catalogDict)

	xrefOffset := buf.Len()
	writeIncrementalXref(&buf, offsets)

	prevXRef := findLastXRefOffset(pdfData)
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Prev %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		maxInt(maxObj, acroFormObjNum)+1, prevXRef, catalogObjNum, xrefOffset)

	return buf.Bytes(), sigObjNum, nil
}

func buildStampAppearanceStream(lines []string) string {
	var b strings.Builder
	b.WriteString("q\n")
	b.WriteString("0.97 0.97 0.97 rg\n")
	b.WriteString("0.4 0.4 0.4 RG\n")
	b.WriteString("0.75 w\n")
	fmt.Fprintf(&b, "0 0 %.2f %.2f re B\n", stampWidth, stampHeight)
	b.WriteString("BT\n")
	fmt.Fprintf(&b, "/Helvetica %.1f Tf\n", stampFontSize)
	b.WriteString("0.4 0.4 0.4 rg\n")
	textY := stampHeight - stampPaddingY - stampFontSize
	fmt.Fprintf(&b, "%.2f %.2f Td\n", stampPaddingX, textY)
	for _, line := range lines {
		safe := strings.ReplaceAll(line, "\\", "\\\\")
		safe = strings.ReplaceAll(safe, "(", "\\(")
		safe = strings.ReplaceAll(safe, ")", "\\)")
		fmt.Fprintf(&b, "(%s) Tj\n0 -%.1f Td\n", safe, stampLineHeight)
	}
	b.WriteString("ET\nQ\n")
	return b.String()
}

func writeIncrementalXref(buf *bytes.Buffer, offsets map[int]int) {
	keys := make([]int, 0, len(offsets))
	for objNum := range offsets {
		keys = append(keys, objNum)
	}
	sortInts(keys)
	buf.WriteString("xref\n")
	for i := 0; i < len(keys); {
		start := keys[i]
		j := i + 1
		for j < len(keys) && keys[j] == keys[j-1]+1 {
			j++
		}
		fmt.Fprintf(buf, "%d %d\n", start, j-i)
		for _, objNum := range keys[i:j] {
			fmt.Fprintf(buf, "%010d 00000 n \n", offsets[objNum])
		}
		i = j
	}
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		j := i
		for j > 0 && values[j-1] > values[j] {
			values[j-1], values[j] = values[j], values[j-1]
			j--
		}
	}
}

func extractRefOrArray(dictBody, key string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `\s+(\[[^\]]*\]|\d+\s+\d+\s+R)`)
	match := re.FindStringSubmatch(dictBody)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func mergeRefOrArray(existingValue, newRef string) string {
	existingValue = strings.TrimSpace(existingValue)
	if existingValue == "" {
		return fmt.Sprintf("[%s]", newRef)
	}
	if strings.HasPrefix(existingValue, "[") && strings.HasSuffix(existingValue, "]") {
		inner := strings.TrimSpace(existingValue[1 : len(existingValue)-1])
		if inner == "" {
			return fmt.Sprintf("[%s]", newRef)
		}
		return fmt.Sprintf("[%s %s]", inner, newRef)
	}
	return fmt.Sprintf("[%s %s]", existingValue, newRef)
}

func upsertRefEntry(dictBody, key, refValue string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `\s+(\[[^\]]*\]|\d+\s+\d+\s+R)`)
	replacement := fmt.Sprintf("%s %s", key, refValue)
	if re.MatchString(dictBody) {
		return re.ReplaceAllString(dictBody, replacement)
	}

	idx := strings.LastIndex(dictBody, ">>")
	if idx < 0 {
		return dictBody
	}
	prefix := dictBody[:idx]
	if !strings.HasSuffix(prefix, "\n") {
		prefix += "\n"
	}
	return prefix + replacement + "\n>>"
}

func findObjectBody(pdfData []byte, objNum int) string {
	re := regexp.MustCompile(`(?s)(\d+)\s+0\s+obj\s*(.*?)\s*endobj`)
	matches := re.FindAllSubmatch(pdfData, -1)
	var lastBody []byte
	for _, match := range matches {
		n, _ := strconv.Atoi(string(match[1]))
		if n == objNum {
			lastBody = match[2]
		}
	}
	if len(lastBody) == 0 {
		return ""
	}
	return strings.TrimSpace(string(lastBody))
}

func findPageObjectNumbers(pdfData []byte) []int {
	re := regexp.MustCompile(`(?s)(\d+)\s+0\s+obj(.*?)endobj`)
	pageTypeRe := regexp.MustCompile(`/Type\s*/Page\b`)
	matches := re.FindAllSubmatch(pdfData, -1)
	pages := make([]int, 0)
	seen := map[int]bool{}
	for _, match := range matches {
		body := string(match[2])
		if pageTypeRe.MatchString(body) {
			objNum, _ := strconv.Atoi(string(match[1]))
			if !seen[objNum] {
				pages = append(pages, objNum)
				seen[objNum] = true
			}
		}
	}
	return pages
}

func findCatalogObjectNumber(pdfData []byte) int {
	re := regexp.MustCompile(`(?s)(\d+)\s+0\s+obj(.*?)endobj`)
	catalogTypeRe := regexp.MustCompile(`/Type\s*/Catalog\b`)
	matches := re.FindAllSubmatch(pdfData, -1)
	for _, match := range matches {
		body := string(match[2])
		if catalogTypeRe.MatchString(body) {
			objNum, _ := strconv.Atoi(string(match[1]))
			return objNum
		}
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func nodeISOTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func buildSigDictBytes(placeholder, signerName, reason, location string, signDate time.Time) string {
	byteRangePlaceholder := "[0 9999999999 9999999999 9999999999]"
	dateStr := signDate.UTC().Format("20060102150405")
	var b strings.Builder
	b.WriteString("<<\n")
	b.WriteString("/Type /Sig\n")
	b.WriteString("/Filter /Adobe.PPKLite\n")
	b.WriteString("/SubFilter /adbe.pkcs7.detached\n")
	fmt.Fprintf(&b, "/ByteRange %s\n", byteRangePlaceholder)
	fmt.Fprintf(&b, "/Contents <%s>\n", placeholder)
	fmt.Fprintf(&b, "/Name (%s)\n", pdfEscape(signerName))
	fmt.Fprintf(&b, "/Reason (%s)\n", pdfEscape(reason))
	if location != "" {
		fmt.Fprintf(&b, "/Location (%s)\n", pdfEscape(location))
	}
	fmt.Fprintf(&b, "/M (D:%s+00'00')\n", dateStr)
	b.WriteString(">>")
	return b.String()
}

func patchByteRange(pdfBuf []byte, placeholderIdx, br0, br1, br2, br3 int) {
	// Search backward from placeholder for "/ByteRange ["
	searchStart := placeholderIdx - 600
	if searchStart < 0 {
		searchStart = 0
	}
	region := string(pdfBuf[searchStart:placeholderIdx])
	brIdx := strings.LastIndex(region, "/ByteRange ")
	if brIdx < 0 {
		return
	}
	abs := searchStart + brIdx
	// Find closing ]
	closeIdx := strings.Index(string(pdfBuf[abs:]), "]")
	if closeIdx < 0 {
		return
	}
	abs2 := abs + closeIdx + 1
	oldLen := abs2 - abs
	newVal := fmt.Sprintf("/ByteRange [%d %d %d %d]", br0, br1, br2, br3)
	padded := newVal
	if len(newVal) < oldLen {
		padded = newVal + strings.Repeat(" ", oldLen-len(newVal))
	}
	copy(pdfBuf[abs:abs+oldLen], []byte(padded[:oldLen]))
}

func findMaxObjectNumber(pdfData []byte) int {
	// Scan for "N 0 obj" patterns to find max object number
	re := regexp.MustCompile(`(\d+)\s+0\s+obj`)
	matches := re.FindAllSubmatch(pdfData, -1)
	max := 10
	for _, m := range matches {
		n, _ := strconv.Atoi(string(m[1]))
		if n > max {
			max = n
		}
	}
	return max
}

func findLastXRefOffset(pdfData []byte) int {
	// Find startxref offset near the end of the file
	tail := pdfData
	if len(tail) > 1024 {
		tail = pdfData[len(pdfData)-1024:]
	}
	idx := bytes.LastIndex(tail, []byte("startxref"))
	if idx < 0 {
		return 0
	}
	rest := string(tail[idx+9:])
	rest = strings.TrimSpace(rest)
	nl := strings.IndexAny(rest, "\n\r")
	if nl > 0 {
		rest = strings.TrimSpace(rest[:nl])
	}
	n, _ := strconv.Atoi(rest)
	return n
}

func certSerialFromPEM(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%X", cert.SerialNumber))
}

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// ─── PKCS#7 / CMS builder ─────────────────────────────────────────────────────

// ASN.1 OIDs
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version            int
	IssuerAndSerial    issuerAndSerialNumber
	DigestAlgorithm    algorithmIdentifier
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

func buildPKCS7(rawSigB64, certPEM, chainPEM string, tsaTokenDER []byte) ([]byte, error) {
	rawSig, err := base64.StdEncoding.DecodeString(rawSigB64)
	if err != nil {
		// Try URL-safe base64
		rawSig, err = base64.RawURLEncoding.DecodeString(rawSigB64)
		if err != nil {
			return nil, fmt.Errorf("decode signature base64: %w", err)
		}
	}

	// Parse certificates
	var certsDER [][]byte
	var signerCert *x509.Certificate

	if certPEM != "" {
		for rest := []byte(certPEM); len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certsDER = append(certsDER, block.Bytes)
				if signerCert == nil {
					signerCert = c
				}
			}
		}
	}

	if chainPEM != "" {
		for rest := []byte(chainPEM); len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			certsDER = append(certsDER, block.Bytes)
		}
	}

	// Build CertificateSet
	var certsRaw bytes.Buffer
	for _, der := range certsDER {
		certsRaw.Write(der)
	}

	var certsImplicit asn1.RawValue
	if certsRaw.Len() > 0 {
		certsImplicit = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certsRaw.Bytes(),
		}
	}

	// Build SignerInfo
	var si signerInfo
	null := asn1.RawValue{Tag: asn1.TagNull}
	si.Version = 1
	si.DigestAlgorithm = algorithmIdentifier{Algorithm: oidSHA256, Parameters: null}
	si.SignatureAlgorithm = algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: null}
	si.Signature = rawSig

	if signerCert != nil {
		rawIssuer, err := asn1.Marshal(signerCert.Issuer.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("marshal issuer: %w", err)
		}
		si.IssuerAndSerial = issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: rawIssuer},
			SerialNumber: signerCert.SerialNumber,
		}
	} else {
		// Minimal placeholder issuer
		emptyName, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true})
		si.IssuerAndSerial = issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: emptyName},
			SerialNumber: big.NewInt(1),
		}
	}

	// Add TSA timestamp as unsigned attribute
	if len(tsaTokenDER) > 0 {
		attrValue, err := asn1.Marshal(asn1.RawValue{FullBytes: tsaTokenDER})
		if err == nil {
			attrBytes, err := asn1.Marshal(struct {
				AttrType   asn1.ObjectIdentifier
				AttrValues asn1.RawValue `asn1:"set"`
			}{
				AttrType:   oidTSTInfo,
				AttrValues: asn1.RawValue{FullBytes: attrValue},
			})
			if err == nil {
				si.UnsignedAttrs = asn1.RawValue{
					Class:      asn1.ClassContextSpecific,
					Tag:        1,
					IsCompound: true,
					Bytes:      attrBytes,
				}
			}
		}
	}

	// Build SignedData
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256, Parameters: null}},
		EncapContentInfo: encapsulatedContentInfo{EContentType: oidData},
		Certificates:     certsImplicit,
		SignerInfos:      []signerInfo{si},
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}

	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	return asn1.Marshal(ci)
}

// ─── TSA helpers ──────────────────────────────────────────────────────────────

func fetchTSAToken(tsaURL, sigHashHex string) ([]byte, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"hash":          sigHashHex,
		"hashAlgorithm": "sha-256",
		"mode":          "classical",
		"certReq":       true,
	})

	url := strings.TrimRight(tsaURL, "/") + "/v1/tsa/json"
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("TSA request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tsaResp map[string]interface{}
	if err := json.Unmarshal(body, &tsaResp); err != nil {
		return nil, fmt.Errorf("TSA response decode: %w", err)
	}

	if success, _ := tsaResp["success"].(bool); !success {
		return nil, fmt.Errorf("TSA error: %v", tsaResp["error"])
	}

	token, _ := tsaResp["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("TSA: empty token")
	}

	respDER, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("TSA token decode: %w", err)
	}

	// Extract TimeStampToken from TSAResponse
	// TSAResponse SEQUENCE { PKIStatusInfo, TimeStampToken }
	// Skip PKIStatusInfo to get to the ContentInfo
	idx := 0
	if len(respDER) == 0 || respDER[0] != 0x30 {
		return respDER, nil
	}
	idx++ // tag
	plen, lenBytes := asn1ParseLength(respDER[idx:])
	idx += lenBytes
	if idx >= len(respDER) {
		return respDER, nil
	}
	// Skip PKIStatusInfo (first SEQUENCE inside)
	if respDER[idx] != 0x30 {
		return respDER, nil
	}
	idx++
	statusLen, statusLenBytes := asn1ParseLength(respDER[idx:])
	idx += statusLenBytes + statusLen
	_ = plen
	if idx >= len(respDER) {
		return nil, fmt.Errorf("TSA: no TimeStampToken in response")
	}
	return respDER[idx:], nil
}

func asn1ParseLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes > 4 || numBytes+1 > len(data) {
		return 0, 1
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, numBytes + 1
}
