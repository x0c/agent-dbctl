//go:build !windows

package daemon

import "net/http"

func wrapPlatformRPCHandler(_ string, next http.Handler) http.Handler {
	return next
}
