package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

type auditFilterOpts struct {
	action  string
	target  string
	opID    string
	actor   string
	since   string
	until   string
	limit   int
	offset  int
	outPath string
	force   bool
}

type auditQueryResult struct {
	Items        []types.AuditEntry `json:"items"`
	TotalMatched int                `json:"total_matched"`
	Returned     int                `json:"returned"`
	Truncated    bool               `json:"truncated"`
	Limit        int                `json:"limit"`
	Offset       int                `json:"offset"`
}

func newAuditCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	auditCmd := &cobra.Command{Use: "audit", Short: "Audit trail verification, query, and export"}

	auditVerifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify append-only SHA-256 hash chain integrity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			st, err := store.Open(cmd.Context(), paths.DBPath)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			defer func() { _ = st.Close() }()
			res, err := st.VerifyAuditChain(cmd.Context())
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if !res.Valid {
				*exitCode = ic.WriteError(types.ErrCodeAuditTampered, false, res.Reason, "Audit chain tampering or sequence gap detected.", map[string]any{"verify": res}, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Audit chain valid (%d entries, head=%s)\n", res.CheckedCount, res.LastHash)
			return nil
		},
	}
	annotateCommand(auditVerifyCmd, RiskRead, "agent-dbctl audit verify --json")

	var listOpts auditFilterOpts
	listOpts.limit = 50
	auditListCmd := &cobra.Command{
		Use:   "list",
		Short: "Query audit log entries with filters and pagination",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			res, code := queryAuditEntries(cmd.Context(), ic, listOpts)
			if code != types.ExitSuccess {
				*exitCode = code
				return nil
			}
			if listOpts.outPath != "" {
				raw, _ := json.MarshalIndent(res, "", "  ")
				absPath, err := WriteAtomicOutput(listOpts.outPath, raw, listOpts.force)
				if err != nil {
					errCode := types.ErrCodeInvalidInput
					if errors.Is(err, errOutputExists) {
						errCode = types.ErrCodeOutputExists
					}
					*exitCode = ic.WriteError(errCode, false, err.Error(), "", nil, nil, types.Meta{})
					return nil
				}
				if ic.JSONMode {
					*exitCode = ic.WriteSuccess(map[string]any{
						"output_file":   absPath,
						"returned":      res.Returned,
						"total_matched": res.TotalMatched,
						"truncated":     res.Truncated,
					}, types.Meta{})
					return nil
				}
				_, _ = fmt.Fprintf(ic.Stdout, "Wrote %d audit entries (total=%d) to %s\n", res.Returned, res.TotalMatched, absPath)
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			if len(res.Items) == 0 {
				_, _ = fmt.Fprintln(ic.Stdout, "No matching audit entries found.")
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, e := range res.Items {
				rows = append(rows, []string{
					fmt.Sprintf("%d", e.Seq),
					e.CreatedAtUTC,
					e.Actor,
					e.Action,
					e.TargetID,
					e.OperationID,
				})
			}
			renderTable(ic.Stdout, []string{"SEQ", "CREATED_AT_UTC", "ACTOR", "ACTION", "TARGET", "OPERATION"}, rows)
			if res.Truncated {
				_, _ = fmt.Fprintf(ic.Stderr, "(showing %d of %d matching entries; use --offset %d for next page)\n", res.Returned, res.TotalMatched, res.Offset+res.Returned)
			}
			return nil
		},
	}
	registerAuditFilterFlags(auditListCmd, &listOpts, 50)
	annotateCommand(auditListCmd, RiskRead, "agent-dbctl audit list --limit 20 --json")

	var exportOpts auditFilterOpts
	exportOpts.limit = 500
	var exportFormat string
	auditExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export filtered audit logs as JSONL or CSV",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			format := strings.ToLower(strings.TrimSpace(exportFormat))
			if format != "jsonl" && format != "csv" {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, fmt.Sprintf("Unsupported --format %q (use jsonl or csv).", exportFormat), "Pass --format jsonl or --format csv.", nil, []string{ic.BinPath + " audit export --format jsonl --json"}, types.Meta{})
				return nil
			}
			res, code := queryAuditEntries(cmd.Context(), ic, exportOpts)
			if code != types.ExitSuccess {
				*exitCode = code
				return nil
			}
			payload, err := marshalAuditExport(format, res.Items)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}

			if exportOpts.outPath != "" {
				absPath, err := WriteAtomicOutput(exportOpts.outPath, payload, exportOpts.force)
				if err != nil {
					errCode := types.ErrCodeInvalidInput
					if errors.Is(err, errOutputExists) {
						errCode = types.ErrCodeOutputExists
					}
					*exitCode = ic.WriteError(errCode, false, err.Error(), "", nil, nil, types.Meta{})
					return nil
				}
				sum := sha256.Sum256(payload)
				hexSum := hex.EncodeToString(sum[:])
				if ic.JSONMode {
					*exitCode = ic.WriteSuccess(map[string]any{
						"output_file":    absPath,
						"format":         format,
						"exported_count": res.Returned,
						"total_matched":  res.TotalMatched,
						"truncated":      res.Truncated,
						"sha256":         hexSum,
					}, types.Meta{})
					return nil
				}
				_, _ = fmt.Fprintf(ic.Stdout, "Exported %d audit entries (%s, sha256=%s) to %s\n", res.Returned, format, hexSum, absPath)
				return nil
			}

			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{
					"format":         format,
					"exported_count": res.Returned,
					"total_matched":  res.TotalMatched,
					"truncated":      res.Truncated,
					"content":        string(payload),
				}, types.Meta{})
				return nil
			}
			_, _ = ic.Stdout.Write(payload)
			return nil
		},
	}
	auditExportCmd.Flags().StringVar(&exportFormat, "format", "jsonl", "Export format (jsonl or csv)")
	registerAuditFilterFlags(auditExportCmd, &exportOpts, 500)
	annotateCommand(auditExportCmd, RiskRead, "agent-dbctl audit export --format jsonl --out audit.jsonl --json")

	auditCmd.AddCommand(auditVerifyCmd, auditListCmd, auditExportCmd)
	return auditCmd
}

func registerAuditFilterFlags(cmd *cobra.Command, opts *auditFilterOpts, defaultLimit int) {
	cmd.Flags().StringVar(&opts.action, "action", "", "Filter by action substring")
	cmd.Flags().StringVar(&opts.target, "target", "", "Filter by target_id or target_ref substring (alias: --db)")
	cmd.Flags().StringVar(&opts.target, "db", "", "Alias for --target")
	_ = cmd.Flags().MarkHidden("db")
	cmd.Flags().StringVar(&opts.opID, "op", "", "Filter by operation_id (alias: --operation)")
	cmd.Flags().StringVar(&opts.opID, "operation", "", "Alias for --op")
	_ = cmd.Flags().MarkHidden("operation")
	cmd.Flags().StringVar(&opts.actor, "actor", "", "Filter by exact actor name")
	cmd.Flags().StringVar(&opts.since, "since", "", "Lower bound UTC timestamp (RFC3339, YYYY-MM-DD, or 30m/24h/7d)")
	cmd.Flags().StringVar(&opts.until, "until", "", "Upper bound UTC timestamp (RFC3339, YYYY-MM-DD, or 30m/24h/7d)")
	cmd.Flags().IntVar(&opts.limit, "limit", defaultLimit, "Maximum entries to return (1..1000)")
	cmd.Flags().IntVar(&opts.offset, "offset", 0, "Result offset for pagination")
	cmd.Flags().StringVar(&opts.outPath, "out", "", "Write output atomically to file path")
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite existing --out file")
}

func queryAuditEntries(ctx context.Context, ic IOContext, opts auditFilterOpts) (auditQueryResult, int) {
	sinceUTC, err := parseAuditTimeFlag(opts.since, false)
	if err != nil {
		return auditQueryResult{}, ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use RFC3339, YYYY-MM-DD, or relative durations like 24h or 7d.", nil, nil, types.Meta{})
	}
	untilUTC, err := parseAuditTimeFlag(opts.until, true)
	if err != nil {
		return auditQueryResult{}, ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use RFC3339, YYYY-MM-DD, or relative durations like 24h or 7d.", nil, nil, types.Meta{})
	}
	limit := opts.limit
	if limit <= 0 {
		limit = 50
	} else if limit > 1000 {
		limit = 1000
	}
	offset := opts.offset
	if offset < 0 {
		offset = 0
	}

	paths, err := config.ResolvePaths(ic.Session)
	if err != nil {
		return auditQueryResult{}, ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
	}

	// Query running daemon when available; otherwise fall back to offline read-only SQLite access.
	if cl, err := daemon.NewClient(paths); err == nil {
		if _, idErr := cl.GetIdentity(ctx); idErr == nil {
			q := url.Values{}
			if opts.action != "" {
				q.Set("action", opts.action)
			}
			if opts.target != "" {
				q.Set("target", opts.target)
			}
			if opts.opID != "" {
				q.Set("operation_id", opts.opID)
			}
			if opts.actor != "" {
				q.Set("actor", opts.actor)
			}
			if sinceUTC != "" {
				q.Set("since", sinceUTC)
			}
			if untilUTC != "" {
				q.Set("until", untilUTC)
			}
			q.Set("limit", strconv.Itoa(limit))
			q.Set("offset", strconv.Itoa(offset))

			var res auditQueryResult
			if rpcErr := cl.DoJSON(ctx, http.MethodGet, "/rpc/v1/audit?"+q.Encode(), nil, &res); rpcErr == nil {
				if res.Items == nil {
					res.Items = []types.AuditEntry{}
				}
				return res, types.ExitSuccess
			}
		}
	}

	st, err := store.Open(ctx, paths.DBPath)
	if err != nil {
		return auditQueryResult{}, ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
	}
	defer func() { _ = st.Close() }()

	items, total, err := st.ListAuditEntriesFiltered(ctx, store.AuditFilter{
		Action:      opts.action,
		TargetID:    opts.target,
		OperationID: opts.opID,
		Actor:       opts.actor,
		SinceUTC:    sinceUTC,
		UntilUTC:    untilUTC,
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		return auditQueryResult{}, ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
	}
	if items == nil {
		items = []types.AuditEntry{}
	}
	return auditQueryResult{
		Items:        items,
		TotalMatched: total,
		Returned:     len(items),
		Truncated:    offset+len(items) < total,
		Limit:        limit,
		Offset:       offset,
	}, types.ExitSuccess
}

func parseAuditTimeFlag(raw string, isUntil bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.HasSuffix(trimmed, "d") && len(trimmed) > 1 {
		days, err := strconv.Atoi(strings.TrimSuffix(trimmed, "d"))
		if err == nil && days >= 0 {
			return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339Nano), nil
		}
	}
	if d, err := time.ParseDuration(trimmed); err == nil && d >= 0 {
		return time.Now().UTC().Add(-d).Format(time.RFC3339Nano), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return t.UTC().Format(time.RFC3339Nano), nil
	}
	if d, err := time.Parse("2006-01-02", trimmed); err == nil {
		if isUntil {
			d = d.Add(24*time.Hour - time.Nanosecond)
		}
		return d.UTC().Format(time.RFC3339Nano), nil
	}
	return "", fmt.Errorf("invalid time filter %q", raw)
}

func marshalAuditExport(format string, items []types.AuditEntry) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "jsonl":
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				return nil, err
			}
		}
	case "csv":
		w := csv.NewWriter(&buf)
		if err := w.Write([]string{"seq", "id", "created_at_utc", "actor", "action", "target_id", "operation_id", "payload_json", "prev_hash", "entry_hash"}); err != nil {
			return nil, err
		}
		for _, item := range items {
			if err := w.Write([]string{
				strconv.FormatInt(item.Seq, 10),
				item.ID,
				item.CreatedAtUTC,
				item.Actor,
				item.Action,
				item.TargetID,
				item.OperationID,
				item.PayloadJSON,
				item.PrevHash,
				item.EntryHash,
			}); err != nil {
				return nil, err
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
	return buf.Bytes(), nil
}
