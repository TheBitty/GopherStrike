package tests

import (
	"GopherStrike/pkg/tools/webvuln"
	"testing"
)

func TestPayloadManager(t *testing.T) {
	// Test creating payload manager with different levels
	pm1 := webvuln.NewPayloadManager(1) // Basic payloads
	pm3 := webvuln.NewPayloadManager(3) // Medium complexity
	pm5 := webvuln.NewPayloadManager(5) // All payloads

	// Test that payload levels are respected
	xssPayloads1 := pm1.GetPayloads(webvuln.VulnTypeXSS)
	xssPayloads3 := pm3.GetPayloads(webvuln.VulnTypeXSS)
	xssPayloads5 := pm5.GetPayloads(webvuln.VulnTypeXSS)

	if len(xssPayloads1) == 0 {
		t.Error("Expected at least some level 1 XSS payloads, but got none")
	}

	if len(xssPayloads3) <= len(xssPayloads1) {
		t.Errorf("Expected more payloads at level 3 than level 1, but got %d vs %d", len(xssPayloads3), len(xssPayloads1))
	}

	if len(xssPayloads5) <= len(xssPayloads3) {
		t.Errorf("Expected more payloads at level 5 than level 3, but got %d vs %d", len(xssPayloads5), len(xssPayloads3))
	}

	// Test different vulnerability types have payloads
	sqlPayloads := pm3.GetPayloads(webvuln.VulnTypeSQLInjection)
	if len(sqlPayloads) == 0 {
		t.Error("Expected SQL Injection payloads, but got none")
	}

	filePayloads := pm3.GetPayloads(webvuln.VulnTypeFileInclusion)
	if len(filePayloads) == 0 {
		t.Error("Expected File Inclusion payloads, but got none")
	}

	// Test payload encoding
	testPayload := "<script>alert('XSS')</script>"
	urlEncoded := pm3.EncodePayload(testPayload, "url")
	if urlEncoded == testPayload {
		t.Error("URL encoding did not change the payload")
	}

	base64Encoded := pm3.EncodePayload(testPayload, "base64")
	if base64Encoded == testPayload {
		t.Error("Base64 encoding did not change the payload")
	}

	// Verify the encoding is different for different methods
	if urlEncoded == base64Encoded {
		t.Error("URL encoding and Base64 encoding produced the same result, which is unexpected")
	}
}
