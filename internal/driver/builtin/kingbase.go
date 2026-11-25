package builtin

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"net"
	"strings"
	"time"

	"gitea.com/kingbase/gokb"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// KingbaseDriver implements KingbaseES (人大金仓) support using pure-Go gokb.
type KingbaseDriver struct{}

var kingbaseDialectConfig = pgWireDialectConfig{
	Engine:          "kingbase",
	DefaultPort:     54321,
	DefaultDatabase: "kingbase",
	ListDatabasesQueries: []string{
		"SELECT datname FROM sys_catalog.sys_database WHERE datallowconn AND LOWER(datname) NOT IN ('template0', 'template1') ORDER BY datname",
		"SELECT datname FROM pg_catalog.pg_database WHERE datallowconn AND LOWER(datname) NOT IN ('template0', 'template1') ORDER BY datname",
		"SELECT current_database()",
	},
	IndexQueries: []string{
		"SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY indexname",
		"SELECT indexname, indexdef FROM sys_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY indexname",
	},
}

func (d *KingbaseDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-kingbase",
		Engine:       "kingbase",
		DisplayName:  "KingbaseES",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "KingbaseES", "zh": "人大金仓 KingbaseES"},
	}
}

func (d *KingbaseDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("kingbase", raw), nil
}

type kingbaseDialerAdapter struct {
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (a kingbaseDialerAdapter) Dial(network, address string) (net.Conn, error) {
	return a.DialTimeout(network, address, 10*time.Second)
}

func (a kingbaseDialerAdapter) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return a.DialContext(ctx, network, address)
}

func (a kingbaseDialerAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return a.dialContext(ctx, network, address)
}

type kingbaseConnector struct {
	dsn    string
	dialer gokb.Dialer
}

func (c *kingbaseConnector) Connect(_ context.Context) (sqldriver.Conn, error) {
	if c.dialer != nil {
		return gokb.DialOpen(c.dialer, c.dsn)
	}
	return gokb.Open(c.dsn)
}

func (c *kingbaseConnector) Driver() sqldriver.Driver {
	return &gokb.Driver{}
}

func mapKingbaseSSLMode(tlsMode string, hasTLSConfig bool) string {
	switch strings.ToLower(strings.TrimSpace(tlsMode)) {
	case "require":
		return "require"
	case "verify-ca":
		return "verify-ca"
	case "verify-full":
		return "verify-full"
	case "disable":
		return "disable"
	default:
		// gokb rejects sslmode=prefer; default to disable unless TLSConfig is supplied.
		if hasTLSConfig {
			return "require"
		}
		return "disable"
	}
}

func buildKingbaseDSN(cfg driver.ConnectionConfig) string {
	return buildPGWireURIWithSSL("kingbase", cfg, kingbaseDialectConfig.DefaultPort, kingbaseDialectConfig.DefaultDatabase, mapKingbaseSSLMode(cfg.TLSMode, cfg.TLSConfig != nil))
}

func openKingbaseSQLDB(ctx context.Context, cfg driver.ConnectionConfig, dsn string) (*sql.DB, error) {
	var baseConn sqldriver.Connector = &kingbaseConnector{dsn: dsn}
	if cfg.DialContext != nil {
		baseConn = &kingbaseConnector{
			dsn:    dsn,
			dialer: kingbaseDialerAdapter{dialContext: cfg.DialContext},
		}
	}
	connector := baseConn
	if cfg.ReadOnly {
		connector = &readOnlyExecConnector{
			inner: baseConn,
			stmts: []string{
				"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
				"SET default_transaction_read_only = on",
				"SET SESSION TRANSACTION READ ONLY",
			},
			errPrefix: "kingbase",
		}
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func isKingbaseSSLRequiredErr(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") || strings.Contains(lower, "pg_hba")
}

func (d *KingbaseDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	dsn := buildKingbaseDSN(cfg)
	db, err := openKingbaseSQLDB(ctx, cfg, dsn)
	if err != nil {
		mode := strings.ToLower(strings.TrimSpace(cfg.TLSMode))
		if (mode == "" || mode == "prefer") && cfg.TLSConfig == nil && isKingbaseSSLRequiredErr(err) {
			reqDSN := buildPGWireURIWithSSL("kingbase", cfg, kingbaseDialectConfig.DefaultPort, kingbaseDialectConfig.DefaultDatabase, "require")
			if reqDB, reqErr := openKingbaseSQLDB(ctx, cfg, reqDSN); reqErr == nil {
				db = reqDB
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return newPGWireConn(db, cfg, kingbaseDialectConfig), nil
}
