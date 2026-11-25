//go:build windows

package daemon

import "net/http"

func wrapPlatformRPCHandler(token string, next http.Handler) http.Handler {
	return WrapRPCTokenMiddleware(token, next)
}
