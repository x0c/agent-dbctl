package builtin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// MongoDriver implements MongoDB support (4.4 - 8.x+) using the official pure-Go mongo-driver/v2.
type MongoDriver struct{}

func (d *MongoDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-mongodb",
		Engine:       "mongodb",
		DisplayName:  "MongoDB",
		Family:       types.FamilyDocument,
		Tier:         "builtin",
		Version:      "1.1.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "MongoDB", "zh": "MongoDB"},
	}
}

func (d *MongoDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("mongodb", raw), nil
}

func (d *MongoDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	clientOpts, err := buildMongoClientOptions(cfg)
	if err != nil {
		return nil, err
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
	mc := &mongoConn{
		client:    client,
		dbName:    dbName,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		mc.caps.Store(&cp)
	}
	return mc, nil
}

func buildMongoClientOptions(cfg driver.ConnectionConfig) (*options.ClientOptions, error) {
	port := cfg.Port
	if port <= 0 {
		port = 27017
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	var hosts []string
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil {
			hosts = append(hosts, h)
		} else {
			hosts = append(hosts, net.JoinHostPort(h, strconv.Itoa(port)))
		}
	}

	clientOpts := options.Client().
		SetHosts(hosts).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second)

	if cfg.Credential.Username != "" {
		authSource := cfg.Params["authSource"]
		if authSource == "" {
			authSource = "admin"
		}
		cred := options.Credential{
			Username:   cfg.Credential.Username,
			Password:   cfg.Credential.Secret,
			AuthSource: authSource,
		}
		if mech := strings.TrimSpace(cfg.Params["authMechanism"]); mech != "" {
			cred.AuthMechanism = mech
		}
		clientOpts.SetAuth(cred)
	}
	if rs := strings.TrimSpace(cfg.Params["replicaSet"]); rs != "" {
		clientOpts.SetReplicaSet(rs)
	}
	if directRaw, ok := cfg.Params["directConnection"]; ok {
		clientOpts.SetDirect(strings.EqualFold(strings.TrimSpace(directRaw), "true") || strings.TrimSpace(directRaw) == "1")
	} else if cfg.DialContext != nil && len(hosts) == 1 && cfg.Params["replicaSet"] == "" {
		// Prevent tunneled single-host endpoints from attempting unreachable internal replica-set discovery.
		clientOpts.SetDirect(true)
	}
	if rpRaw := strings.TrimSpace(cfg.Params["readPreference"]); rpRaw != "" {
		if rp, err := parseMongoReadPref(rpRaw); err == nil {
			clientOpts.SetReadPreference(rp)
		} else {
			return nil, err
		}
	} else if cfg.ReadOnly {
		clientOpts.SetReadPreference(readpref.SecondaryPreferred())
	}
	if apiVer := strings.TrimSpace(cfg.Params["serverAPIVersion"]); apiVer == "1" {
		clientOpts.SetServerAPIOptions(options.ServerAPI(options.ServerAPIVersion1))
	}
	if ct := strings.TrimSpace(cfg.Params["connectTimeoutMS"]); ct != "" {
		if ms, err := strconv.Atoi(ct); err == nil && ms > 0 {
			clientOpts.SetConnectTimeout(time.Duration(ms) * time.Millisecond)
		}
	}
	if sst := strings.TrimSpace(cfg.Params["serverSelectionTimeoutMS"]); sst != "" {
		if ms, err := strconv.Atoi(sst); err == nil && ms > 0 {
			clientOpts.SetServerSelectionTimeout(time.Duration(ms) * time.Millisecond)
		}
	}
	if cfg.TLSConfig != nil {
		clientOpts.SetTLSConfig(cfg.TLSConfig)
	}
	if cfg.DialContext != nil {
		clientOpts.SetDialer(mongoDialerAdapter{fn: cfg.DialContext})
	}
	return clientOpts, nil
}

func parseMongoReadPref(raw string) (*readpref.ReadPref, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "primary":
		return readpref.Primary(), nil
	case "primarypreferred":
		return readpref.PrimaryPreferred(), nil
	case "secondary":
		return readpref.Secondary(), nil
	case "secondarypreferred":
		return readpref.SecondaryPreferred(), nil
	case "nearest":
		return readpref.Nearest(), nil
	default:
		return nil, fmt.Errorf("unsupported mongodb readPreference %q", raw)
	}
}

type mongoDialerAdapter struct {
	fn func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (m mongoDialerAdapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.fn(ctx, network, address)
}

type mongoConn struct {
	client    *mongo.Client
	dbName    string
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *mongoConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *mongoConn) ResetSession(ctx context.Context) error {
	if c.client == nil {
		return fmt.Errorf("mongodb client is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.client.Ping(pingCtx, nil)
}

func (c *mongoConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var info bson.M
	err := c.client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info)
	if err == nil {
		ver, _ := info["version"].(string)
		hints := driver.DialectHints{BuildInfoModules: extractStringSlice(info["modules"])}
		caps := driver.DetectServerCapabilities("mongodb", ver, hints)
		c.caps.Store(&caps)
		return types.PingResult{
			Engine:        "mongodb",
			Dialect:       caps.Dialect,
			Reachable:     true,
			ServerVersion: ver,
			Capabilities:  &caps,
			LatencyMs:     time.Since(start).Milliseconds(),
		}, nil
	}

	// Shared Atlas tiers, DocumentDB, or restricted roles may block buildInfo.
	// Fall back to ping + hello (MongoDB 4.4.2+/5.0+) or legacy isMaster (<=4.4).
	if pingErr := c.client.Ping(ctx, nil); pingErr != nil {
		return types.PingResult{Engine: "mongodb", Reachable: false, LatencyMs: time.Since(start).Milliseconds(), Error: pingErr.Error()}, pingErr
	}
	var ver string
	var maxWire int
	var helloOut bson.M
	if hErr := c.client.Database(c.dbName).RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&helloOut); hErr == nil {
		if mw, ok := helloOut["maxWireVersion"]; ok {
			ver = fmt.Sprintf("wire_v%v", mw)
			if n, ok := asInt64(mw); ok {
				maxWire = int(n)
			}
		}
	} else if imErr := c.client.Database(c.dbName).RunCommand(ctx, bson.D{{Key: "isMaster", Value: 1}}).Decode(&helloOut); imErr == nil {
		if mw, ok := helloOut["maxWireVersion"]; ok {
			ver = fmt.Sprintf("wire_v%v", mw)
			if n, ok := asInt64(mw); ok {
				maxWire = int(n)
			}
		}
	}
	caps := driver.DetectServerCapabilities("mongodb", ver, driver.DialectHints{MaxWireVersion: maxWire})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "mongodb",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}

func extractStringSlice(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case bson.A:
		out := make([]string, 0, len(xs))
		for _, item := range xs {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(xs))
		for _, item := range xs {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (c *mongoConn) ListDatabases(ctx context.Context) ([]string, error) {
	names, err := c.client.ListDatabaseNames(ctx, bson.D{})
	if err == nil {
		return names, nil
	}
	// Least-privilege users may only list databases they are authorized on (MongoDB 4.0.5+).
	names, authErr := c.client.ListDatabaseNames(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
	if authErr == nil {
		return names, nil
	}
	if c.dbName != "" {
		return []string{c.dbName}, nil
	}
	return nil, err
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

	if cur, ok := out["cursor"].(bson.M); ok {
		return c.collectMongoCursor(ctx, cur, opts, start)
	}

	normDoc := normalizeBSON(out)
	return docsToExecResult([]any{normDoc}, opts, start)
}

func (c *mongoConn) collectMongoCursor(ctx context.Context, firstCursor bson.M, opts driver.ExecOpts, start time.Time) (*types.ExecResult, error) {
	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
	var outDocs []any

	appendBatch := func(batch bson.A) {
		for _, item := range batch {
			norm := normalizeBSON(item)
			if buf.TryAcceptRow(norm) {
				outDocs = append(outDocs, norm)
			} else if buf.Truncated {
				return
			}
		}
	}

	if fb, ok := firstCursor["firstBatch"].(bson.A); ok {
		appendBatch(fb)
	}

	cursorID, _ := asInt64(firstCursor["id"])
	ns, _ := firstCursor["ns"].(string)
	coll := collectionFromNS(ns)

	for cursorID != 0 && !buf.Truncated && coll != "" {
		getMoreCmd := bson.D{
			{Key: "getMore", Value: cursorID},
			{Key: "collection", Value: coll},
		}
		if opts.MaxRows > 0 && opts.MaxRows-buf.FetchedRows > 0 {
			getMoreCmd = append(getMoreCmd, bson.E{Key: "batchSize", Value: opts.MaxRows - buf.FetchedRows + 1})
		}
		var gmOut bson.M
		if err := c.client.Database(c.dbName).RunCommand(ctx, getMoreCmd).Decode(&gmOut); err != nil {
			c.killMongoCursor(cursorID, coll)
			return nil, err
		}
		cur, ok := gmOut["cursor"].(bson.M)
		if !ok {
			break
		}
		if nb, ok := cur["nextBatch"].(bson.A); ok {
			appendBatch(nb)
		}
		cursorID, _ = asInt64(cur["id"])
	}

	if cursorID != 0 && coll != "" {
		c.killMongoCursor(cursorID, coll)
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

func (c *mongoConn) killMongoCursor(cursorID int64, coll string) {
	if cursorID == 0 || coll == "" {
		return
	}
	kctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.client.Database(c.dbName).RunCommand(kctx, bson.D{
		{Key: "killCursors", Value: coll},
		{Key: "cursors", Value: bson.A{cursorID}},
	}).Err()
}

func collectionFromNS(ns string) string {
	_, coll, ok := strings.Cut(ns, ".")
	if !ok {
		return ""
	}
	return coll
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
	case bson.Decimal128:
		return x.String()
	case bson.Timestamp:
		return fmt.Sprintf("%d:%d", x.T, x.I)
	case bson.Regex:
		return map[string]string{"pattern": x.Pattern, "options": x.Options}
	case bson.Symbol:
		return string(x)
	case bson.JavaScript:
		return string(x)
	case bson.MinKey:
		return "$minKey"
	case bson.MaxKey:
		return "$maxKey"
	case bson.Binary:
		if utf8.Valid(x.Data) {
			return string(x.Data)
		}
		return base64.StdEncoding.EncodeToString(x.Data)
	case float64:
		if math.IsNaN(x) {
			return "NaN"
		}
		if math.IsInf(x, 1) {
			return "Infinity"
		}
		if math.IsInf(x, -1) {
			return "-Infinity"
		}
		return x
	default:
		return x
	}
}

func (c *mongoConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *mongoConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c.closeErr = c.client.Disconnect(ctx)
	})
	return c.closeErr
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
