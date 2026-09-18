package bunnysign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	baseURL := "https://cdn.example.com"
	path := "/videos/1080p/intro.mp4"
	secret := "secret-key-12345"

	// 1. Without secret returns plain URL
	plain := Sign(baseURL, path, "", Options{})
	if plain != "https://cdn.example.com/videos/1080p/intro.mp4" {
		t.Fatalf("expected plain url, got %s", plain)
	}

	// 2. Sign with TTL
	signed := Sign(baseURL, path, secret, Options{
		TTL: 1 * time.Hour,
	})

	if !strings.HasPrefix(signed, "https://cdn.example.com/videos/1080p/intro.mp4?token=HS256-") {
		t.Fatalf("unexpected signed URL prefix: %s", signed)
	}

	valid, err := Verify(signed, secret, "")
	if err != nil || !valid {
		t.Fatalf("expected signature to verify, err=%v, valid=%v", err, valid)
	}

	// Verify fails with wrong secret
	valid, err = Verify(signed, "wrong-key", "")
	if valid || err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got valid=%v, err=%v", valid, err)
	}

	// 3. Sign with client IP restriction
	clientIP := "203.0.113.19"
	signedWithIP := Sign(baseURL, path, secret, Options{
		TTL:    1 * time.Hour,
		UserIP: clientIP,
	})

	valid, err = Verify(signedWithIP, secret, clientIP)
	if err != nil || !valid {
		t.Fatalf("expected IP-bound signature to verify, err=%v", err)
	}

	// Fails when requesting from a different IP
	valid, err = Verify(signedWithIP, secret, "198.51.100.2")
	if valid || err != ErrInvalidSignature {
		t.Fatalf("expected IP mismatch failure, got valid=%v, err=%v", valid, err)
	}

	// 4. TokenPath signing (directory level)
	signedDir := Sign(baseURL, path, secret, Options{
		TTL:       1 * time.Hour,
		TokenPath: "/videos/1080p/",
	})
	if !strings.Contains(signedDir, "token_path=") && !strings.Contains(signedDir, "token=") {
		t.Fatalf("expected token in %s", signedDir)
	}

	// 5. Expired token
	expiredURL := Sign(baseURL, path, secret, Options{
		Expires: time.Now().Add(-1 * time.Minute),
	})
	valid, err = Verify(expiredURL, secret, "")
	if valid || err != ErrExpired {
		t.Fatalf("expected ErrExpired, got valid=%v, err=%v", valid, err)
	}
}

func TestPurgeClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("AccessKey") != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	client := NewPurgeClient("test-api-key", WithHTTPClient(server.Client()), WithPullZoneID("12345"))
	client.purgeURL = server.URL

	if err := client.PurgeURL(context.Background(), "https://cdn.example.com/test.jpg"); err != nil {
		t.Fatalf("PurgeURL failed: %v", err)
	}
}

func BenchmarkSign(b *testing.B) {
	baseURL := "https://cdn.example.com"
	path := "/images/avatars/user-987654321/header.webp"
	secret := "production-ultra-secret-signing-key-value"
	opts := Options{TTL: 2 * time.Hour}

	b.ReportAllocs()
	for b.Loop() {
		_ = Sign(baseURL, path, secret, opts)
	}
}

func BenchmarkVerify(b *testing.B) {
	baseURL := "https://cdn.example.com"
	path := "/images/avatars/user-987654321/header.webp"
	secret := "production-ultra-secret-signing-key-value"
	signed := Sign(baseURL, path, secret, Options{TTL: 2 * time.Hour})

	b.ReportAllocs()
	for b.Loop() {
		_, _ = Verify(signed, secret, "")
	}
}
