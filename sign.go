package bunnysign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrExpired indicates a signed URL token has expired.
	ErrExpired = errors.New("bunnysign: token expired")
	// ErrInvalidSignature indicates the signature does not match.
	ErrInvalidSignature = errors.New("bunnysign: invalid signature")
	// ErrMissingToken indicates the URL does not contain a signature token.
	ErrMissingToken = errors.New("bunnysign: missing token parameter")
	// ErrMissingExpires indicates the URL does not contain an expiration timestamp.
	ErrMissingExpires = errors.New("bunnysign: missing expires parameter")
)

// Options specifies URL signing parameters.
type Options struct {
	// Expires sets the absolute expiration time. Takes precedence over TTL.
	Expires time.Time
	// TTL is added to the current time to compute the expiration timestamp.
	TTL time.Duration
	// UserIP optionally restricts the token to a specific client IP address.
	UserIP string
	// TokenPath specifies an optional directory path to sign instead of the full file path.
	TokenPath string
	// UseHourlyCache truncates the expiration time to the current hour for deterministic caching.
	UseHourlyCache bool
}

// Sign signs a URL path with BunnyCDN HMAC-SHA256 token authentication.
// If secret is empty, the plain joined URL is returned.
func Sign(baseURL, filePath, secret string, opts Options) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	if secret == "" {
		return baseURL + filePath
	}

	cleanIP := normalizeIP(opts.UserIP)

	var expires int64
	if !opts.Expires.IsZero() {
		expires = opts.Expires.Unix()
	} else {
		ttl := opts.TTL
		if ttl <= 0 {
			ttl = 2 * time.Hour
		}
		now := time.Now()
		if opts.UseHourlyCache {
			expires = now.Truncate(time.Hour).Add(ttl).Unix()
		} else {
			expires = now.Add(ttl).Unix()
		}
	}

	var expiresBuf [24]byte
	expiresBytes := strconv.AppendInt(expiresBuf[:0], expires, 10)

	if !strings.Contains(filePath, "?") && opts.TokenPath == "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(filePath))
		mac.Write(expiresBytes)
		if cleanIP != "" {
			mac.Write([]byte(cleanIP))
		}

		sum := mac.Sum(nil)
		var b64Buf [64]byte
		n := base64.RawURLEncoding.EncodedLen(len(sum))
		base64.RawURLEncoding.Encode(b64Buf[:n], sum)

		var out strings.Builder
		out.Grow(len(baseURL) + len(filePath) + 7 + 6 + n + 9 + len(expiresBytes))
		out.WriteString(baseURL)
		out.WriteString(filePath)
		out.WriteString("?token=HS256-")
		out.Write(b64Buf[:n])
		out.WriteString("&expires=")
		out.Write(expiresBytes)
		return out.String()
	}

	parsedURL, err := url.Parse(baseURL + filePath)
	if err != nil {
		return baseURL + filePath
	}

	params := parsedURL.Query()
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "token" && k != "expires" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	signaturePath := parsedURL.Path
	if opts.TokenPath != "" {
		signaturePath = opts.TokenPath
	} else if tokenPath := params.Get("token_path"); tokenPath != "" {
		signaturePath = tokenPath
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signaturePath))
	mac.Write(expiresBytes)

	var paramBuilder strings.Builder
	for _, k := range keys {
		values := params[k]
		slices.Sort(values)
		for _, v := range values {
			if v != "" {
				mac.Write([]byte(k))
				mac.Write([]byte("="))
				mac.Write([]byte(v))

				paramBuilder.WriteString("&")
				paramBuilder.WriteString(k)
				paramBuilder.WriteString("=")
				paramBuilder.WriteString(url.QueryEscape(v))
			}
		}
	}

	if cleanIP != "" {
		mac.Write([]byte(cleanIP))
	}

	sum := mac.Sum(nil)
	var b64Buf [64]byte
	n := base64.RawURLEncoding.EncodedLen(len(sum))
	base64.RawURLEncoding.Encode(b64Buf[:n], sum)
	tokenStr := "HS256-" + string(b64Buf[:n])

	var out strings.Builder
	out.Grow(len(parsedURL.Scheme) + 3 + len(parsedURL.Host) + len(parsedURL.Path) + 7 + len(tokenStr) + paramBuilder.Len() + 9 + len(expiresBytes))
	out.WriteString(parsedURL.Scheme)
	out.WriteString("://")
	out.WriteString(parsedURL.Host)
	out.WriteString(parsedURL.Path)
	out.WriteString("?token=")
	out.WriteString(tokenStr)
	out.WriteString(paramBuilder.String())
	out.WriteString("&expires=")
	out.Write(expiresBytes)

	return out.String()
}

// Verify validates a signed BunnyCDN URL against the secret and optional client IP.
func Verify(rawURL, secret string, userIP string) (bool, error) {
	if secret == "" {
		return false, errors.New("bunnysign: secret key is required")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return false, err
	}

	q := u.Query()
	token := q.Get("token")
	if token == "" {
		return false, ErrMissingToken
	}

	expiresStr := q.Get("expires")
	if expiresStr == "" {
		return false, ErrMissingExpires
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return false, ErrInvalidSignature
	}

	if time.Now().Unix() > expires {
		return false, ErrExpired
	}

	cleanIP := normalizeIP(userIP)

	keys := make([]string, 0, len(q))
	for k := range q {
		if k != "token" && k != "expires" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	signaturePath := u.Path
	if tokenPath := q.Get("token_path"); tokenPath != "" {
		signaturePath = tokenPath
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signaturePath))
	mac.Write([]byte(expiresStr))

	for _, k := range keys {
		values := q[k]
		slices.Sort(values)
		for _, v := range values {
			if v != "" {
				mac.Write([]byte(k))
				mac.Write([]byte("="))
				mac.Write([]byte(v))
			}
		}
	}

	if cleanIP != "" {
		mac.Write([]byte(cleanIP))
	}

	expectedSum := mac.Sum(nil)
	var b64Buf [64]byte
	n := base64.RawURLEncoding.EncodedLen(len(expectedSum))
	base64.RawURLEncoding.Encode(b64Buf[:n], expectedSum)

	rawTokenHash, ok := strings.CutPrefix(token, "HS256-")
	if !ok {
		return false, ErrInvalidSignature
	}
	if subtle.ConstantTimeCompare([]byte(rawTokenHash), b64Buf[:n]) != 1 {
		return false, ErrInvalidSignature
	}

	return true, nil
}

func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap().String()
	}
	return raw
}
