package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

// IOContext captures separate TTY detection for stdin/stdout and output switches.
type IOContext struct {
	StdinIsTTY  bool
	StdoutIsTTY bool
	JSONMode    bool
	NoColor     bool
	NoInput     bool
	Version     string
	Session     string
	Context     string
	Mode        string
	BinPath     string
	Stdout      io.Writer
	Stderr      io.Writer
}

// DetectIO initializes IOContext using separate isatty checks on stdin and stdout.
func DetectIO(forceJSON, noColor, noInput bool, version, session string) IOContext {
	stdinTTY := term.IsTerminal(int(os.Stdin.Fd()))
	stdoutTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		noColor = true
	}
	jsonMode := forceJSON || !stdoutTTY
	nonInteractive := noInput || !stdinTTY || !stdoutTTY

	binPath, err := os.Executable()
	if err != nil || binPath == "" {
		binPath = "agent-dbctl"
	}

	return IOContext{
		StdinIsTTY:  stdinTTY,
		StdoutIsTTY: stdoutTTY,
		JSONMode:    jsonMode,
		NoColor:     noColor,
		NoInput:     nonInteractive,
		Version:     version,
		Session:     session,
		BinPath:     binPath,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}
}

func (ioCtx IOContext) WriteSuccess(data any, meta types.Meta) int {
	if meta.Version == "" {
		meta.Version = ioCtx.Version
	}
	if meta.Session == "" {
		meta.Session = ioCtx.Session
	}
	if meta.Context == "" && ioCtx.Context != "" {
		meta.Context = ioCtx.Context
	}
	if meta.Mode == "" && ioCtx.Mode != "" {
		meta.Mode = ioCtx.Mode
	}
	if ioCtx.JSONMode {
		env := types.Envelope{
			OK:    true,
			Data:  data,
			Error: nil,
			Meta:  meta,
		}
		enc := json.NewEncoder(ioCtx.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(env)
		return types.ExitSuccess
	}
	return types.ExitSuccess
}

func rewriteContextNextCommands(ioCtx IOContext, cmds []string) []string {
	if ioCtx.Mode != string(config.ContextModeRemote) || ioCtx.Context == "" || len(cmds) == 0 {
		return cmds
	}
	out := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		trimmed := strings.TrimSpace(cmd)
		if trimmed == "" || strings.Contains(trimmed, "--context") {
			out = append(out, cmd)
			continue
		}
		if strings.Contains(trimmed, " serve") || strings.Contains(trimmed, " context ") {
			out = append(out, cmd)
			continue
		}
		if strings.HasSuffix(trimmed, " --json") {
			out = append(out, strings.TrimSuffix(trimmed, " --json")+" --context "+ioCtx.Context+" --json")
		} else {
			out = append(out, trimmed+" --context "+ioCtx.Context)
		}
	}
	return out
}

func (ioCtx IOContext) WriteError(code string, retryable bool, message, hint string, ctxMap map[string]any, nextCmds []string, meta types.Meta) int {
	if meta.Version == "" {
		meta.Version = ioCtx.Version
	}
	if meta.Session == "" {
		meta.Session = ioCtx.Session
	}
	if meta.Context == "" && ioCtx.Context != "" {
		meta.Context = ioCtx.Context
	}
	if meta.Mode == "" && ioCtx.Mode != "" {
		meta.Mode = ioCtx.Mode
	}
	nextCmds = rewriteContextNextCommands(ioCtx, nextCmds)
	exitCode := types.ExitCodeForError(code)
	if ioCtx.JSONMode {
		env := types.Envelope{
			OK:   false,
			Data: nil,
			Error: &types.ErrorBody{
				Code:         code,
				Retryable:    retryable,
				Message:      message,
				Hint:         hint,
				Context:      ctxMap,
				NextCommands: nextCmds,
			},
			Meta: meta,
		}
		enc := json.NewEncoder(ioCtx.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(env)
		return exitCode
	}

	_, _ = fmt.Fprintf(ioCtx.Stderr, "Error [%s]: %s\n", code, message)
	if hint != "" {
		_, _ = fmt.Fprintf(ioCtx.Stderr, "Hint: %s\n", hint)
	}
	for _, cmd := range nextCmds {
		_, _ = fmt.Fprintf(ioCtx.Stderr, "Next: %s\n", cmd)
	}
	return exitCode
}

func renderTable(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
}

// WriteAtomicOutput writes bytes safely to outPath (refuses symlinks and requires force to overwrite).
func WriteAtomicOutput(outPath string, data []byte, force bool) (string, error) {
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to write through symlink %s", abs)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("refusing non-regular output path %s", abs)
		}
		if !force {
			return "", fmt.Errorf("%w: output file %s already exists (pass --force to overwrite)", errOutputExists, abs)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".agent-dbctl-out-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return "", err
	}
	cleanup = false
	return abs, nil
}

var errOutputExists = fmt.Errorf("output exists")
