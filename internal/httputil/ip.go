package httputil

import (
	"net"
	"net/http"
	"strings"
)

// ExtractClientIP returns the client IP from the request.
// When trustProxy is true, X-Forwarded-For and X-Real-IP headers are checked first.
// Falls back to r.RemoteAddr with proper IPv6 handling via net.SplitHostPort.
func ExtractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return ip
}
