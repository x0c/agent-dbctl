package builtin

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"

	opengauss "gitcode.com/opengauss/openGauss-connector-go-pq"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// OpenGaussDriver implements openGauss, Huawei GaussDB, Vastbase, MogDB, and GBase 8c support
// using pure-Go openGauss-connector-go-pq (including RFC5802 SHA256 and national-crypto SM3 auth).
type OpenGaussDriver struct{}

var openGaussDialectConfig = pgWireDialectConfig{
	Engine:          "opengauss",
	DefaultPort:     5432,
	DefaultDatabase: "postgres",
	ListDatabasesQueries: []string{
		"SELECT datname FROM pg_catalog.pg_database WHERE datistemplate = false AND datallowconn = true ORDER BY datname",
		"SELECT datname FROM sys_catalog.sys_database WHERE datistemplate = false AND datallowconn = true ORDER BY datname",
		"SELECT current_database()",
	},
	IndexQueries: []string{
		"SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY indexname",
		"SELECT indexname, indexdef FROM sys_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY indexname",
	},
}

func (d *OpenGaussDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-opengauss",
		Engine:       "opengauss",
		DisplayName:  "openGauss / GaussDB",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "openGauss / GaussDB", "zh": "openGauss / GaussDB"},
	}
}

func (d *OpenGaussDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("opengauss", raw), nil
}

type openGaussConnector struct {
	inner sqldriver.Connector
}

func (c *openGaussConnector) Connect(ctx context.Context) (sqldriver.Conn, error) {
	return c.inner.Connect(ctx)
}

func (c *openGaussConnector) Driver() sqldriver.Driver {
	return c.inner.Driver()
}

func buildOpenGaussDSN(cfg driver.ConnectionConfig) string {
	// openGauss-connector-go-pq ParseURL only accepts postgres:// or postgresql:// URI schemes.
	return buildPGWireURI("postgres", cfg, openGaussDialectConfig.DefaultPort, openGaussDialectConfig.DefaultDatabase)
}

func (d *OpenGaussDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	dsn := buildOpenGaussDSN(cfg)
	parsedCfg, err := opengauss.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// openGauss-connector-go-pq DialOpen leaves DialFunc untouched; wire DialFunc and LookupFunc directly on Config.
	if cfg.DialContext != nil {
		parsedCfg.DialFunc = cfg.DialContext
		parsedCfg.LookupFunc = func(_ context.Context, host string) ([]string, error) {
			return []string{host}, nil
		}
	}
	if cfg.TLSConfig != nil {
		parsedCfg.TLSConfig = cfg.TLSConfig
		for _, fb := range parsedCfg.Fallbacks {
			fb.TLSConfig = cfg.TLSConfig
		}
	}
	baseConn, err := opengauss.NewConnectorConfig(parsedCfg)
	if err != nil {
		return nil, err
	}
	var connector sqldriver.Connector = &openGaussConnector{inner: baseConn}
	if cfg.ReadOnly {
		connector = &readOnlyExecConnector{
			inner: baseConn,
			stmts: []string{
				"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
				"SET default_transaction_read_only = on",
				"SET SESSION TRANSACTION READ ONLY",
			},
			errPrefix: "opengauss",
		}
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return newPGWireConn(db, cfg, openGaussDialectConfig), nil
}
