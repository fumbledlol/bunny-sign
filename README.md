# bunny-sign

[![Go Reference](https://pkg.go.dev/badge/github.com/fumbledlol/bunny-sign.svg)](https://pkg.go.dev/github.com/fumbledlol/bunny-sign)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Go library for BunnyCDN token authentication, signed URLs, and edge cache purging.

## Features

- URL path signing with HMAC-SHA256 and fast paths for query-free URLs
- Directory token paths (`token_path`) and sorted query parameter signing
- Client IP restriction with automatic port stripping and IPv4-mapped IPv6 unmapping
- Signature verification using constant-time comparisons
- Cache purging for individual URLs, cache tags, and entire pull zones
- Standard library only, no external dependencies

## Installation

```bash
go get github.com/fumbledlol/bunny-sign
```

## Quick start

### Signing URLs

```go
package main

import (
	"fmt"
	"time"

	bunnysign "github.com/fumbledlol/bunny-sign"
)

func main() {
	baseURL := "https://cdn.example.com"
	filePath := "/videos/1080p/intro.mp4"
	secretKey := "your-bunny-token-key"

	// Sign with 2-hour TTL
	signedURL := bunnysign.Sign(baseURL, filePath, secretKey, bunnysign.Options{
		TTL: 2 * time.Hour,
	})
	fmt.Println("Signed URL:", signedURL)

	// Sign restricted to client IP
	signedIPURL := bunnysign.Sign(baseURL, filePath, secretKey, bunnysign.Options{
		TTL:    1 * time.Hour,
		UserIP: "203.0.113.19",
	})
	fmt.Println("IP-restricted URL:", signedIPURL)
}
```

### Verifying signed URLs

```go
valid, err := bunnysign.Verify(signedURL, secretKey, clientIP)
if err != nil || !valid {
	// Expired or invalid token
}
```

### Edge cache purge API

```go
client := bunnysign.NewPurgeClient("your-api-key", bunnysign.WithPullZoneID("12345"))

// Purge specific URLs
err := client.PurgeURL(ctx, "https://cdn.example.com/asset.png")

// Purge edge cache tags
err = client.PurgeCacheTag(ctx, "12345", "user-profiles", "avatars")

// Purge entire pull zone
err = client.PurgePullZone(ctx, "12345")
```

## Benchmarks

```
BenchmarkSign-12        1410318    856.1 ns/op     776 B/op    10 allocs/op
BenchmarkVerify-12       796447   1719   ns/op    1200 B/op    14 allocs/op
```

## License

[MIT](LICENSE)
