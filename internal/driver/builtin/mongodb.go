package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// MongoDriver implements MongoDB support using the official pure-Go mongo-driver/v2.
type MongoDriver struct{}

func (d *MongoDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-mongodb",
		Engine:       "mongodb",
		DisplayName:  "MongoDB",
		Family:       types.FamilyDocument,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "MongoDB", "zh": "MongoDB"},
	}
}

func (d *MongoDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("mongodb", raw), nil
}

func (d *MongoDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	port := cfg.Port
	if port <= 0 {
		port = 27017
	}
	hostAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))
	clientOpts := options.Client().
		SetHosts([]string{hostAddr}).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second)

	if cfg.Credential.Username != "" {
		authSource := cfg.Params["authSource"]
		if authSource == "" {
			authSource = "admin"
		}
		clientOpts.SetAuth(options.Credential{
			Username:   cfg.Credential.Username,
			Password:   cfg.Credential.Secret,
			AuthSource: authSource,
		})
	}
	if cfg.TLSConfig != nil {
		clientOpts.SetTLSConfig(cfg.TLSConfig)
	}
	if cfg.DialContext != nil {
		clientOpts.SetDialer(mongoDialerAdapter{fn: cfg.DialContext})
	}

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}
	dbName := cfg.DatabaseName
	if dbName == "" {
		dbName = "admin"
	}
	return &mongoConn{client: client, dbName: dbName, cfg: cfg}, nil
}

type mongoDialerAdapter struct {
	fn func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (m mongoDialerAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.fn(ctx, network, address)
}

type mongoConn struct {
	client *mongo.Client
	dbName string
	cfg    driver.ConnectionConfig
}

func (c *mongoConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var info bson.M
	err := c.client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "mongodb", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	ver, _ := info["version"].(string)
	return types.PingResult{Engine: "mongodb", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *mongoConn) ListDatabases(ctx context.Context) ([]string, error) {
	return c.client.ListDatabaseNames(ctx, bson.D{})
}

func (c *mongoConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "mongo_queryPlanner",
	}
	cmdDoc, err := parseMongoCommandDoc(raw)
	if err != nil {
		report.Warnings = append(report.Warnings, "Preflight requires JSON RunCommand format; static classification still enforced")
		return report, nil
	}
	explainCmd := bson.D{{Key: "explain", Value: cmdDoc}, {Key: "verbosity", Value: "queryPlanner"}}
	var res bson.M
	if err := c.client.Database(c.dbName).RunCommand(ctx, explainCmd).Decode(&res); err != nil {
		report.Warnings = append(report.Warnings, "Mongo explain failed: "+err.Error())
		return report, nil
	}
	norm := normalizeBSON(res)
	report.PlanRaw = norm
	rawBytes, _ := json.Marshal(norm)
	if strings.Contains(string(rawBytes), "COLLSCAN") {
		report.FullScan = true
	}
	report.PlanSummary = fmt.Sprintf("queryPlanner full_scan=%v", report.FullScan)
	return report, nil
}

func (c *mongoConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)

	if lower == "show dbs" || lower == "show databases" {
		names, err := c.ListDatabases(ctx)
		if err != nil {
			return nil, err
		}
		return docsToExecResult(namesToDocs("database", names), opts, start)
	}
	if lower == "show collections" || lower == "show tables" {
		names, err := c.client.Database(c.dbName).ListCollectionNames(ctx, bson.D{})
		if err != nil {
			return nil, err
		}
		return docsToExecResult(namesToDocs("collection", names), opts, start)
	}

	cmdDoc, err := parseMongoCommandDoc(trimmed)
	if err != nil {
		return nil, err
	}
	var out bson.M
	if err := c.client.Database(c.dbName).RunCommand(ctx, cmdDoc).Decode(&out); err != nil {
		return nil, err
	}
	var docs []any
	if cur, ok := out["cursor"].(bson.M); ok {
		if fb, ok := cur["firstBatch"].(bson.A); ok {
			docs = append(docs, fb...)
		}
	}
	if len(docs) == 0 {
		docs = []any{out}
	}
	normDocs := make([]any, len(docs))
	for i, d := range docs {
		normDocs[i] = normalizeBSON(d)
	}
	return docsToExecResult(normDocs, opts, start)
}

func normalizeBSON(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bson.D:
		m := make(map[string]any, len(x))
		for _, e := range x {
			m[e.Key] = normalizeBSON(e.Value)
		}
		return m
	case bson.M:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = normalizeBSON(val)
		}
		return m
	case bson.A:
		arr := make([]any, len(x))
		for i, item := range x {
			arr[i] = normalizeBSON(item)
		}
		return arr
	case bson.ObjectID:
		return x.Hex()
	case bson.DateTime:
		return x.Time().UTC().Format(time.RFC3339Nano)
	case bson.Binary:
		return x.Data
	default:
		return x
	}
}

func (c *mongoConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *mongoConn) Close() error {
	if c.cfg.CloseHook != nil {
		_ = c.cfg.CloseHook()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.client.Disconnect(ctx)
}

func parseMongoCommandDoc(raw string) (bson.D, error) {
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return nil, fmt.Errorf("MongoDB driver expects JSON RunCommand document (e.g. {\"find\": \"orders\", \"filter\": {}})")
	}
	var doc bson.D
	if err := bson.UnmarshalExtJSON([]byte(raw), false, &doc); err != nil {
		return nil, fmt.Errorf("parse MongoDB command JSON: %w", err)
	}
	return doc, nil
}

func namesToDocs(key string, names []string) []any {
	docs := make([]any, len(names))
	for i, n := range names {
		docs[i] = map[string]any{key: n}
	}
	return docs
}

func docsToExecResult(docs []any, opts driver.ExecOpts, start time.Time) (*types.ExecResult, error) {
	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
	var outDocs []any
	for _, doc := range docs {
		if buf.TryAcceptRow(doc) {
			outDocs = append(outDocs, doc)
		} else if buf.Truncated {
			break
		}
	}
	return &types.ExecResult{
		Family:        types.FamilyDocument,
		Documents:     outDocs,
		FetchedRows:   buf.FetchedRows,
		ReturnedRows:  len(outDocs),
		ReturnedBytes: buf.ReturnedBytes,
		Truncated:     buf.Truncated,
		CutoffReason:  buf.CutoffReason,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}
