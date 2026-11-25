package webui

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

//go:embed all:dist
var embeddedFS embed.FS

type cachedAsset struct {
	contentType string
	raw         []byte
	gz          []byte
}

func isCompressibleExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".js", ".mjs", ".css", ".html", ".svg", ".json", ".txt", ".xml", ".map":
		return true
	default:
		return false
	}
}

func buildAssetCache(sub fs.FS) map[string]cachedAsset {
	out := make(map[string]cachedAsset)
	_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == ".gitkeep" {
			return nil
		}
		raw, err := fs.ReadFile(sub, p)
		if err != nil {
			return nil
		}
		ext := path.Ext(p)
		ct := mime.TypeByExtension(ext)
		if ct == "" {
			ct = http.DetectContentType(raw)
		}
		item := cachedAsset{contentType: ct, raw: raw}
		if isCompressibleExt(ext) && len(raw) >= 256 {
			var buf bytes.Buffer
			if zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression); err == nil {
				_, wErr := zw.Write(raw)
				cErr := zw.Close()
				if wErr == nil && cErr == nil && buf.Len() < len(raw) {
					item.gz = buf.Bytes()
				}
			}
		}
		out[p] = item
		return nil
	})
	return out
}

func writeCachedAsset(w http.ResponseWriter, r *http.Request, item cachedAsset, cacheControl string) {
	w.Header().Set("Content-Type", item.contentType)
	w.Header().Set("Cache-Control", cacheControl)
	if len(item.gz) > 0 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Length", strconv.Itoa(len(item.gz)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(item.gz)
		}
		return
	}
	if len(item.gz) > 0 {
		w.Header().Set("Vary", "Accept-Encoding")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(item.raw)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(item.raw)
	}
}

// Handler serves the embedded TypeScript Web Console SPA with pre-gzipped assets and cache headers.
func Handler() http.Handler {
	sub, err := fs.Sub(embeddedFS, "dist")
	if err != nil {
		return http.NotFoundHandler()
	}
	assets := buildAssetCache(sub)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		if strings.HasPrefix(clean, "/api/") || clean == "/healthz" {
			http.NotFound(w, r)
			return
		}
		trimmed := strings.TrimPrefix(clean, "/")
		if trimmed != "" {
			if item, ok := assets[trimmed]; ok {
				cc := "no-cache"
				if strings.HasPrefix(trimmed, "assets/") {
					cc = "public, max-age=31536000, immutable"
				}
				writeCachedAsset(w, r, item, cc)
				return
			}
		}
		if idx, ok := assets["index.html"]; ok {
			writeCachedAsset(w, r, idx, "no-cache")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("agent-dbctl web UI bundle not built yet. Run make build-web."))
	})
}
