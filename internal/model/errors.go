package model

import "errors"

var (
	ErrTargetNameRequired    = errors.New("target name is required")
	ErrTargetDomainRequired  = errors.New("target domain is required")
	ErrTargetSchemeInvalid   = errors.New("target scheme must be http or https")
	ErrTargetPortsRequired   = errors.New("target ports cannot be empty")
	ErrResolverServerInvalid = errors.New("resolver server address is invalid")
)

// IsLocalPermissionError reports whether an error message indicates a local
// permission problem (e.g. insufficient privileges for ICMP sockets).
func IsLocalPermissionError(msg string) bool {
	lower := toLowerASCII(msg)
	return contains(lower, "operation not permitted") || contains(lower, "permission denied")
}

// toLowerASCII is a tiny ASCII-only strings.ToLower to avoid the full Unicode
// tables in this hot path.
func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	return indexString(s, substr) >= 0
}

func indexString(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}
