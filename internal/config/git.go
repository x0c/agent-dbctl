package config

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NormalizeGitRemote canonicalizes a Git remote URL (HTTPS, SSH, SCP-like, git://, or shorthand)
// into a portable, secret-free identifier (<host[:port]>/<owner>/<repo>) without trailing .git.
func NormalizeGitRemote(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			scheme := strings.ToLower(u.Scheme)
			if scheme == "file" {
				return trimTrailingDotGit(filepath.Clean(u.Path))
			}
			host := strings.ToLower(u.Hostname())
			if host != "" {
				port := u.Port()
				if port != "" && !isDefaultGitPort(scheme, port) {
					host = net.JoinHostPort(host, port)
				} else if strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
				p := trimGitPath(u.Path)
				if p == "" {
					return host
				}
				return host + "/" + p
			}
		}
	}

	if !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, ".") && !strings.HasPrefix(s, "~") {
		if colonIdx := strings.IndexByte(s, ':'); colonIdx > 0 {
			left := s[:colonIdx]
			right := s[colonIdx+1:]
			if !strings.ContainsAny(left, `/\`) && right != "" {
				// Distinguish host:port/path from SCP-like [user@]host:path.
				if !strings.Contains(left, "@") {
					if slashIdx := strings.IndexByte(right, '/'); slashIdx > 0 && isDigits(right[:slashIdx]) {
						host := strings.ToLower(strings.TrimSpace(left))
						port := right[:slashIdx]
						rest := trimGitPath(right[slashIdx+1:])
						if !isDefaultGitPort("ssh", port) && !isDefaultGitPort("https", port) && !isDefaultGitPort("http", port) {
							host = host + ":" + port
						}
						if rest == "" {
							return host
						}
						return host + "/" + rest
					}
				}
				if atIdx := strings.LastIndexByte(left, '@'); atIdx >= 0 {
					left = left[atIdx+1:]
				}
				left = strings.TrimPrefix(strings.TrimSuffix(left, "]"), "[")
				host := strings.ToLower(strings.TrimSpace(left))
				p := trimGitPath(right)
				if len(host) > 1 {
					if p == "" {
						return host
					}
					return host + "/" + p
				}
			}
		}
		if slashIdx := strings.IndexByte(s, '/'); slashIdx > 0 {
			host := strings.ToLower(strings.TrimSpace(s[:slashIdx]))
			p := trimGitPath(s[slashIdx+1:])
			if host != "" {
				if p == "" {
					return host
				}
				return host + "/" + p
			}
		}
	}

	return trimTrailingDotGit(strings.TrimRight(s, "/"))
}

// NormalizeGitRemotes normalizes and case-insensitively deduplicates a slice of Git remotes while preserving order.
func NormalizeGitRemotes(raws []string) []string {
	out := make([]string, 0, len(raws))
	seen := make(map[string]struct{}, len(raws))
	for _, r := range raws {
		n := NormalizeGitRemote(r)
		if n == "" {
			continue
		}
		key := strings.ToLower(n)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}
	return out
}

// RepoNameFromGitRemote extracts the repository leaf name from a canonical Git remote.
func RepoNameFromGitRemote(remote string) string {
	norm := NormalizeGitRemote(remote)
	if norm == "" {
		return ""
	}
	idx := strings.LastIndexByte(norm, '/')
	if idx < 0 || idx == len(norm)-1 {
		return ""
	}
	return norm[idx+1:]
}

// DetectGitRemotes inspects local Git remotes for cwd (supporting worktrees and subdirectories).
// It prioritizes "origin" first and silently returns nil when cwd is not a Git repository or git is unavailable.
func DetectGitRemotes(ctx context.Context, cwd string) []string {
	if strings.TrimSpace(cwd) == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil || cwd == "" {
			return nil
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "git", "-C", cwd, "remote", "-v")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseGitRemoteVerboseOutput(string(out))
}

func parseGitRemoteVerboseOutput(raw string) []string {
	var originURLs []string
	var otherURLs []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tabIdx := strings.IndexByte(line, '\t')
		if tabIdx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:tabIdx])
		rest := strings.TrimSpace(line[tabIdx+1:])
		rest = strings.TrimSuffix(rest, " (fetch)")
		rest = strings.TrimSuffix(rest, " (push)")
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		if strings.EqualFold(name, "origin") {
			originURLs = append(originURLs, rest)
		} else {
			otherURLs = append(otherURLs, rest)
		}
	}
	combined := append(originURLs, otherURLs...)
	res := NormalizeGitRemotes(combined)
	if len(res) == 0 {
		return nil
	}
	return res
}

func trimGitPath(p string) string {
	p = strings.Trim(p, "/")
	p = trimTrailingDotGit(p)
	return strings.Trim(p, "/")
}

func trimTrailingDotGit(s string) string {
	if len(s) >= 4 && strings.EqualFold(s[len(s)-4:], ".git") {
		return s[:len(s)-4]
	}
	return s
}

func isDefaultGitPort(scheme, port string) bool {
	switch scheme {
	case "ssh", "git+ssh":
		return port == "22"
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	case "git":
		return port == "9418"
	default:
		return false
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
