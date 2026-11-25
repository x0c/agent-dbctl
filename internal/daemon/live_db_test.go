package daemon_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

func requireLiveEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENT_DBCTL_LIVE_TEST") != "1" {
		t.Skip("skipping live multi-DB tests (set AGENT_DBCTL_LIVE_TEST=1 to enable)")
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func approvePendingHTTP(t *testing.T, webURL, approvalID, approvalURL, note string) {
	t.Helper()
	u, err := url.Parse(approvalURL)
	if err != nil {
		t.Fatalf("parse approval url %q: %v", approvalURL, err)
	}
	tok := u.Query().Get("token")
	body, _ := json.Marshal(map[string]string{
		"reviewer": "live-tester",
		"note":     note,
		"token":    tok,
	})
	req, _ := http.NewRequest(http.MethodPost, webURL+"/api/v1/approvals/"+approvalID+"/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", webURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("approve HTTP failed: resp=%+v err=%v", resp, err)
	}
	_ = resp.Body.Close()
}

func rejectPendingHTTP(t *testing.T, webURL, approvalID, approvalURL, note string) {
	t.Helper()
	u, err := url.Parse(approvalURL)
	if err != nil {
		t.Fatalf("parse approval url %q: %v", approvalURL, err)
	}
	tok := u.Query().Get("token")
	body, _ := json.Marshal(map[string]string{
		"reviewer": "live-dba",
		"note":     note,
		"token":    tok,
	})
	req, _ := http.NewRequest(http.MethodPost, webURL+"/api/v1/approvals/"+approvalID+"/reject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", webURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("reject HTTP failed: resp=%+v err=%v", resp, err)
	}
	_ = resp.Body.Close()
}

func waitOpTerminal(t *testing.T, ctx context.Context, svc interface {
	GetOperationStatus(context.Context, string) (types.ExecResponse, error)
}, opID string) types.ExecResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		res, err := svc.GetOperationStatus(ctx, opID)
		if err == nil && res.Status != types.OpWaitingApproval && res.Status != types.OpPending && res.Status != types.OpRunning {
			return res
		}
		time.Sleep(50 * time.Millisecond)
	}
	res, err := svc.GetOperationStatus(ctx, opID)
	t.Fatalf("operation %s did not finish in time (last=%+v err=%v)", opID, res, err)
	return res
}

func TestLiveMultiDatabaseEngines(t *testing.T) {
	requireLiveEnv(t)

	host := envOr("AGENT_DBCTL_TEST_HOST", "127.0.0.1")
	rwPass := os.Getenv("AGENT_DBCTL_TEST_RW_PASS")
	roPass := os.Getenv("AGENT_DBCTL_TEST_RO_PASS")
	redisPass := envOr("AGENT_DBCTL_TEST_REDIS_PASS", rwPass)
	if rwPass == "" || roPass == "" {
		t.Fatal("AGENT_DBCTL_TEST_RW_PASS and AGENT_DBCTL_TEST_RO_PASS must be set")
	}

	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	sys, err := svc.Store().UpsertSystem(ctx, "live-test", types.System{
		Slug:           "live-commerce",
		Name:           "Live Commerce",
		Owner:          "qa",
		WorkspacePaths: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatalf("upsert system: %v", err)
	}

	seedCred := func(name string, level types.AccessLevel, user, pass string) string {
		t.Helper()
		c, err := svc.Store().UpsertCredentialProfile(ctx, "live-test", types.CredentialProfile{
			Name:        name,
			Kind:        types.CredKeychain,
			AccessLevel: level,
			Username:    user,
		})
		if err != nil {
			t.Fatalf("upsert cred %s: %v", name, err)
		}
		if err := svc.Secrets().Put(ctx, "cred:"+c.ID, pass); err != nil {
			t.Fatalf("set secret %s: %v", name, err)
		}
		return c.ID
	}

	pgRW := seedCred("pg-rw", types.AccessReadWrite, "adb_rw", rwPass)
	pgRO := seedCred("pg-ro", types.AccessReadOnly, "adb_ro", roPass)
	redisCred := seedCred("redis-auth", types.AccessReadWrite, "", redisPass)

	// ---- 1. PostgreSQL ----
	t.Run("PostgreSQL", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-pg",
			Engine: "postgres",
			Host:   host,
			Port:   25432,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert pg instance: %v", err)
		}
		devTgt, err := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/pg",
			Alias:           "live-dev-pg",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		if err != nil {
			t.Fatalf("upsert pg dev target: %v", err)
		}
		prodTgt, err := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/pg",
			Alias:           "live-prod-pg",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		if err != nil {
			t.Fatalf("upsert pg prod target: %v", err)
		}

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve pg prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("PG Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("PG DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}

		// Dev YOLO read
		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT id, customer_email, amount_cents, status FROM orders WHERE id <= 5 ORDER BY id",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || devRes.Result == nil || len(devRes.Result.Rows) != 5 {
			t.Fatalf("PG dev select failed: %+v err=%v", devRes, err)
		}

		// Prod indexed read should run immediately without approval (using RO credential)
		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42 LIMIT 1",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("PG prod indexed select failed: %+v err=%v", prodRead, err)
		}

		// Prod Seq Scan should escalate via EXPLAIN preflight
		seqPreflight, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, status FROM orders WHERE status = 'pending' LIMIT 10",
			Preflight:        true,
		})
		if err != nil || seqPreflight.Preflight == nil || !seqPreflight.Preflight.FullScan {
			t.Fatalf("expected PG preflight FullScan=true, got %+v err=%v", seqPreflight, err)
		}
		if seqPreflight.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected PG seq scan to escalate to require_approval, got %+v", seqPreflight.Evaluation)
		}

		// Prod write approval -> approve -> execute -> verify
		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE orders SET amount_cents = amount_cents + 1 WHERE id = 42",
			Reason:           "Live PG approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected PG write waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved pg test")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result == nil || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected PG approved write affected_rows=1, got %+v", done)
		}

		// Prod write rejection
		rej, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "DELETE FROM orders WHERE id = 42",
			Reason:           "Test rejection",
			Wait:             false,
		})
		if err != nil || rej.Status != types.OpWaitingApproval {
			t.Fatalf("expected PG delete waiting_approval, got %+v err=%v", rej, err)
		}
		rejectPendingHTTP(t, srv.WebURL(), rej.ApprovalID, rej.ApprovalURL, "No deletes allowed")
		rejDone := waitOpTerminal(t, ctx, svc, rej.OperationID)
		if rejDone.Status != types.OpRejected || rejDone.ReviewerNote != "No deletes allowed" {
			t.Fatalf("expected rejected PG op with note, got %+v", rejDone)
		}
	})

	// ---- 2. MySQL ----
	t.Run("MySQL", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-mysql",
			Engine: "mysql",
			Host:   host,
			Port:   23306,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert mysql inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/mysql",
			Alias:           "live-dev-mysql",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/mysql",
			Alias:           "live-prod-mysql",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve mysql prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("MySQL Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("MySQL DiscoverDatabases failed: %v %v", dbs, err)
		}

		res, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42 LIMIT 1",
			Wait:             true,
		})
		if err != nil || res.Status != types.OpSucceeded || len(res.Result.Rows) != 1 {
			t.Fatalf("MySQL select failed: %+v err=%v", res, err)
		}
		// Ensure VARCHAR decoded as plain UTF-8 string, not base64 bytes.
		emailVal, ok := res.Result.Rows[0][1].(string)
		if !ok || !strings.Contains(emailVal, "@") {
			t.Fatalf("expected readable email string, got %T (%v)", res.Result.Rows[0][1], res.Result.Rows[0][1])
		}

		// Preflight full table scan
		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, status FROM orders WHERE status = 'pending' LIMIT 5",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected MySQL preflight FullScan=true, got %+v err=%v", pf, err)
		}

		// Approved write
		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE orders SET amount_cents = amount_cents + 1 WHERE id = 42",
			Reason:           "Live MySQL approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected MySQL waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved mysql")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected MySQL write affected=1, got %+v", done)
		}
	})

	// ---- 3. MongoDB ----
	t.Run("MongoDB", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-mongo",
			Engine: "mongodb",
			Host:   host,
			Port:   27027,
			Role:   types.RolePrimary,
			Params: map[string]string{"authSource": "orders_test"},
		})
		if err != nil {
			t.Fatalf("upsert mongo inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/mongo",
			Alias:           "live-dev-mongo",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/mongo",
			Alias:           "live-prod-mongo",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve mongo prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("Mongo Ping failed: %+v", ping)
		}

		cols, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "show collections",
			Wait:             true,
		})
		if err != nil || cols.Status != types.OpSucceeded || len(cols.Result.Documents) == 0 {
			t.Fatalf("Mongo show collections failed: %+v err=%v", cols, err)
		}

		findRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            `{"find": "orders", "filter": {"order_id": 42}, "limit": 1}`,
			Wait:             true,
		})
		if err != nil || findRes.Status != types.OpSucceeded || len(findRes.Result.Documents) != 1 {
			t.Fatalf("Mongo find failed: %+v err=%v", findRes, err)
		}
		// Ensure returned document is normalized JSON object (contains "customer_email"), not [{"Key":...,"Value":...}].
		b, _ := json.Marshal(findRes.Result.Documents[0])
		if !strings.Contains(string(b), `"customer_email"`) {
			t.Fatalf("expected normalized JSON doc with customer_email, got %s", string(b))
		}

		// Bounded COLLSCAN (limit <= 1000) stays safe; unbounded COLLSCAN must set FullScan=true.
		boundedPF, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            `{"find": "orders", "filter": {"status": "pending"}, "limit": 5}`,
			Preflight:        true,
		})
		if err != nil || boundedPF.Preflight == nil || boundedPF.Preflight.FullScan {
			t.Fatalf("expected bounded Mongo COLLSCAN FullScan=false, got pf=%+v err=%v", boundedPF.Preflight, err)
		}
		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            `{"find": "orders", "filter": {"status": "pending"}}`,
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected Mongo preflight COLLSCAN FullScan=true, got pf=%+v resp=%+v err=%v", pf.Preflight, pf, err)
		}

		// Approved Mongo update write
		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            `{"update": "orders", "updates": [{"q": {"order_id": 42}, "u": {"$inc": {"amount_cents": 1}}}]}`,
			Reason:           "Live Mongo approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected Mongo waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved mongo")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded {
			t.Fatalf("expected Mongo approved write to succeed, got %+v", done)
		}
	})

	// ---- 4. Redis ----
	t.Run("Redis", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-redis",
			Engine: "redis",
			Host:   host,
			Port:   26379,
			Role:   types.RoleStandalone,
		})
		if err != nil {
			t.Fatalf("upsert redis inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/redis",
			Alias:           "live-dev-redis",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "0",
			ROCredentialID:  redisCred,
			RWCredentialID:  redisCred,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/redis",
			Alias:           "live-prod-redis",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "0",
			ROCredentialID:  redisCred,
			RWCredentialID:  redisCred,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve redis prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("Redis Ping failed: %+v", ping)
		}

		// Safe read on prod
		getRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "GET order:1001",
			Wait:             true,
		})
		if err != nil || getRes.Status != types.OpSucceeded || getRes.Result.KVResult == nil {
			t.Fatalf("Redis GET failed: %+v err=%v", getRes, err)
		}

		// High-cost read KEYS * must require approval on prod
		keysDry, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "KEYS *",
			DryRun:           true,
		})
		if err != nil || keysDry.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected KEYS * to require approval on prod, got %+v err=%v", keysDry, err)
		}

		// Dev write + read
		setRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SET agent_dbctl:probe ok",
			Wait:             true,
		})
		if err != nil || setRes.Status != types.OpSucceeded {
			t.Fatalf("Redis dev SET failed: %+v err=%v", setRes, err)
		}
	})

	// ---- 5. ClickHouse ----
	t.Run("ClickHouse", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-clickhouse",
			Engine: "clickhouse",
			Host:   host,
			Port:   29000,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert clickhouse inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/clickhouse",
			Alias:           "live-dev-ch",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/clickhouse",
			Alias:           "live-prod-ch",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve ch prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("ClickHouse Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("ClickHouse DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("ClickHouse InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT id, customer_email, amount_cents, status FROM orders WHERE id <= 5 ORDER BY id",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 5 {
			t.Fatalf("ClickHouse dev select failed: %+v err=%v", devRes, err)
		}

		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42 LIMIT 1",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("ClickHouse prod PK select failed: %+v err=%v", prodRead, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, status FROM orders WHERE status = 'pending' LIMIT 10",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected ClickHouse preflight FullScan=true, got %+v err=%v", pf, err)
		}
		if pf.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected ClickHouse full scan to escalate to require_approval, got %+v", pf.Evaluation)
		}

		ins, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "INSERT INTO orders (id, customer_email, amount_cents, status) VALUES (9999, 'live-ch@example.com', 100, 'paid')",
			Reason:           "Live ClickHouse approval test",
			Wait:             false,
		})
		if err != nil || ins.Status != types.OpWaitingApproval {
			t.Fatalf("expected ClickHouse write waiting_approval, got %+v err=%v", ins, err)
		}
		approvePendingHTTP(t, srv.WebURL(), ins.ApprovalID, ins.ApprovalURL, "approved ch")
		done := waitOpTerminal(t, ctx, svc, ins.OperationID)
		if done.Status != types.OpSucceeded {
			t.Fatalf("expected ClickHouse approved write to succeed, got %+v", done)
		}
	})

	// ---- 6. MSSQL ----
	t.Run("MSSQL", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-mssql",
			Engine: "mssql",
			Host:   host,
			Port:   21433,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert mssql inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/mssql",
			Alias:           "live-dev-mssql",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/mssql",
			Alias:           "live-prod-mssql",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve mssql prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("MSSQL Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("MSSQL DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("MSSQL InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT TOP 5 id, customer_email, amount_cents, status FROM orders WHERE id <= 5 ORDER BY id",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 5 {
			t.Fatalf("MSSQL dev select failed: %+v err=%v", devRes, err)
		}

		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("MSSQL prod PK select failed: %+v err=%v", prodRead, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT TOP 10 id, status FROM orders WHERE status = 'pending'",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected MSSQL preflight FullScan=true, got %+v err=%v", pf, err)
		}

		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE orders SET amount_cents = amount_cents + 1 WHERE id = 42",
			Reason:           "Live MSSQL approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected MSSQL waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved mssql")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected MSSQL write affected=1, got %+v", done)
		}
	})

	// ---- 7. Oracle ----
	t.Run("Oracle", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-oracle",
			Engine: "oracle",
			Host:   host,
			Port:   21521,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert oracle inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/oracle",
			Alias:           "live-dev-oracle",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "FREEPDB1",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/oracle",
			Alias:           "live-prod-oracle",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "FREEPDB1",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve oracle prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("Oracle Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "FREEPDB1")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("Oracle DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, devTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("Oracle InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT id, customer_email, amount_cents, status FROM orders WHERE id <= 5 ORDER BY id",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 5 {
			t.Fatalf("Oracle dev select failed: %+v err=%v", devRes, err)
		}

		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("Oracle prod PK select failed: %+v err=%v", prodRead, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, status FROM orders WHERE status = 'pending' FETCH FIRST 10 ROWS ONLY",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected Oracle preflight FullScan=true, got %+v err=%v", pf, err)
		}

		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE orders SET amount_cents = amount_cents + 1 WHERE id = 42",
			Reason:           "Live Oracle approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected Oracle waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved oracle")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected Oracle write affected=1, got %+v", done)
		}
	})

	// ---- 8. Elasticsearch ----
	t.Run("Elasticsearch", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-elasticsearch",
			Engine: "elasticsearch",
			Host:   host,
			Port:   29200,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert es inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/es",
			Alias:           "live-dev-es",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders",
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/es",
			Alias:           "live-prod-es",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders",
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve es prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable {
			t.Fatalf("Elasticsearch Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, "", "orders")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("Elasticsearch DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("Elasticsearch InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "POST /orders/_search\n{\"query\":{\"term\":{\"order_id\":42}},\"size\":1}",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Documents) != 1 {
			t.Fatalf("Elasticsearch dev search failed: %+v err=%v", devRes, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            `{"index":"orders","query":{"match_all":{}}}`,
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan || pf.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected Elasticsearch match_all preflight escalation, got %+v err=%v", pf, err)
		}

		docWrite, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "POST /orders/_doc/9999\n{\"order_id\":9999,\"customer_email\":\"es@example.com\",\"amount_cents\":100,\"status\":\"paid\"}",
			Reason:           "Live ES approval test",
			Wait:             false,
		})
		if err != nil || docWrite.Status != types.OpWaitingApproval {
			t.Fatalf("expected ES write waiting_approval, got %+v err=%v", docWrite, err)
		}
		approvePendingHTTP(t, srv.WebURL(), docWrite.ApprovalID, docWrite.ApprovalURL, "approved es")
		done := waitOpTerminal(t, ctx, svc, docWrite.OperationID)
		if done.Status != types.OpSucceeded {
			t.Fatalf("expected ES approved write to succeed, got %+v", done)
		}
	})

	// ---- 9. OpenGauss ----
	t.Run("OpenGauss", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-opengauss",
			Engine: "opengauss",
			Host:   host,
			Port:   25433,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert opengauss inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/opengauss",
			Alias:           "live-dev-opengauss",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/opengauss",
			Alias:           "live-prod-opengauss",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  pgRO,
			RWCredentialID:  pgRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve opengauss prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable || ping.Dialect != "opengauss" {
			t.Fatalf("OpenGauss Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, pgRW, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("OpenGauss DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("OpenGauss InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT id, customer_email, amount_cents, status FROM orders WHERE id <= 5 ORDER BY id",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 5 {
			t.Fatalf("OpenGauss dev select failed: %+v err=%v", devRes, err)
		}

		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, customer_email, status FROM orders WHERE id = 42 LIMIT 1",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("OpenGauss prod indexed select failed: %+v err=%v", prodRead, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT id, status FROM orders WHERE status = 'pending' LIMIT 10",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan || pf.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected OpenGauss seq scan preflight escalation, got %+v err=%v", pf, err)
		}

		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE orders SET amount_cents = amount_cents + 1 WHERE id = 42",
			Reason:           "Live OpenGauss approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected OpenGauss waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved opengauss")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result == nil || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected OpenGauss write affected=1, got %+v", done)
		}
	})

	// ---- 10. Dameng DM8 ----
	t.Run("Dameng", func(t *testing.T) {
		dmRW := seedCred("dameng-rw", types.AccessReadWrite, "ADB_RW", rwPass)
		dmRO := seedCred("dameng-ro", types.AccessReadOnly, "ADB_RO", roPass)
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-dameng",
			Engine: "dameng",
			Host:   host,
			Port:   25236,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert dameng inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/dameng",
			Alias:           "live-dev-dameng",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "ADB_RW",
			ROCredentialID:  dmRO,
			RWCredentialID:  dmRW,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/dameng",
			Alias:           "live-prod-dameng",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "ADB_RO",
			ROCredentialID:  dmRO,
			RWCredentialID:  dmRW,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve dameng prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable || ping.Dialect != "dameng" {
			t.Fatalf("Dameng Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, dmRW, "ADB_RW")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("Dameng DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("Dameng InspectSchema (synonym orders) failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT ID, CUSTOMER_EMAIL, STATUS FROM ADB_RW.ORDERS WHERE ID <= 5 ORDER BY ID",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 5 {
			t.Fatalf("Dameng dev select failed: %+v err=%v", devRes, err)
		}

		prodRead, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT ID, CUSTOMER_EMAIL, STATUS FROM ORDERS WHERE ID = 42",
			Wait:             true,
		})
		if err != nil || prodRead.Status != types.OpSucceeded || len(prodRead.Result.Rows) != 1 {
			t.Fatalf("Dameng prod PK select failed: %+v err=%v", prodRead, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT ID, STATUS FROM ORDERS WHERE STATUS = 'pending' FETCH FIRST 5 ROWS ONLY",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan {
			t.Fatalf("expected Dameng preflight FullScan=true, got pf=%+v resp=%+v err=%v", pf.Preflight, pf, err)
		}

		upd, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "UPDATE ADB_RW.ORDERS SET AMOUNT_CENTS = AMOUNT_CENTS + 1 WHERE ID = 42",
			Reason:           "Live Dameng approval test",
			Wait:             false,
		})
		if err != nil || upd.Status != types.OpWaitingApproval {
			t.Fatalf("expected Dameng waiting_approval, got %+v err=%v", upd, err)
		}
		approvePendingHTTP(t, srv.WebURL(), upd.ApprovalID, upd.ApprovalURL, "approved dameng")
		done := waitOpTerminal(t, ctx, svc, upd.OperationID)
		if done.Status != types.OpSucceeded || done.Result == nil || done.Result.AffectedRows == nil || *done.Result.AffectedRows != 1 {
			t.Fatalf("expected Dameng write affected=1, got %+v", done)
		}
	})

	// ---- 11. TDengine ----
	t.Run("TDengine", func(t *testing.T) {
		tdPass := envOr("AGENT_DBCTL_TEST_TDENGINE_PASS", "taosdata")
		tdCred := seedCred("tdengine-rw", types.AccessReadWrite, "root", tdPass)
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-tdengine",
			Engine: "tdengine",
			Host:   host,
			Port:   26041,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert tdengine inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/tdengine",
			Alias:           "live-dev-tdengine",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  tdCred,
			RWCredentialID:  tdCred,
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/tdengine",
			Alias:           "live-prod-tdengine",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders_test",
			ROCredentialID:  tdCred,
			RWCredentialID:  tdCred,
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve tdengine prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable || ping.Dialect != "tdengine" {
			t.Fatalf("TDengine Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, tdCred, "orders_test")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("TDengine DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("TDengine InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "SELECT order_id, customer_email, status FROM orders WHERE order_id = 42 LIMIT 1",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Rows) != 1 {
			t.Fatalf("TDengine dev select failed: %+v err=%v", devRes, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "SELECT order_id, status FROM orders WHERE status = 'pending' LIMIT 5",
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.Supported {
			t.Fatalf("TDengine preflight failed: %+v err=%v", pf, err)
		}

		ins, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "INSERT INTO ord_cn VALUES ('2026-11-25 10:00:09.000', 99, 'user99@example.com', 9900, 'paid')",
			Reason:           "Live TDengine approval test",
			Wait:             false,
		})
		if err != nil || ins.Status != types.OpWaitingApproval {
			t.Fatalf("expected TDengine waiting_approval, got %+v err=%v", ins, err)
		}
		approvePendingHTTP(t, srv.WebURL(), ins.ApprovalID, ins.ApprovalURL, "approved tdengine")
		done := waitOpTerminal(t, ctx, svc, ins.OperationID)
		if done.Status != types.OpSucceeded {
			t.Fatalf("expected TDengine approved insert to succeed, got %+v", done)
		}
	})

	// ---- 12. Easysearch ----
	t.Run("Easysearch", func(t *testing.T) {
		inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
			Name:   "live-easysearch",
			Engine: "easysearch",
			Host:   host,
			Port:   29201,
			Role:   types.RolePrimary,
		})
		if err != nil {
			t.Fatalf("upsert easysearch inst: %v", err)
		}
		devTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/dev/easysearch",
			Alias:           "live-dev-easysearch",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    "orders",
		})
		prodTgt, _ := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
			Ref:             "live-commerce/prod/easysearch",
			Alias:           "live-prod-easysearch",
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "prod",
			InstanceID:      inst.ID,
			DatabaseName:    "orders",
		})

		prodDet, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
		if err != nil {
			t.Fatalf("resolve easysearch prod target: %v", err)
		}
		ping := svc.PingTarget(ctx, prodDet)
		if !ping.Reachable || ping.Dialect != "easysearch" {
			t.Fatalf("Easysearch Ping failed: %+v", ping)
		}
		dbs, err := svc.DiscoverInstance(ctx, inst.ID, "", "orders")
		if err != nil || len(dbs) == 0 {
			t.Fatalf("Easysearch DiscoverDatabases failed: dbs=%v err=%v", dbs, err)
		}
		if _, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "orders", "", 0); err != nil {
			t.Fatalf("Easysearch InspectSchema failed: %v", err)
		}

		devRes, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: devTgt.Alias,
			Query:            "POST /orders/_search\n{\"query\":{\"term\":{\"order_id\":42}},\"size\":1}",
			Wait:             true,
		})
		if err != nil || devRes.Status != types.OpSucceeded || len(devRes.Result.Documents) != 1 {
			t.Fatalf("Easysearch dev search failed: %+v err=%v", devRes, err)
		}

		pf, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            `{"index":"orders","query":{"match_all":{}}}`,
			Preflight:        true,
		})
		if err != nil || pf.Preflight == nil || !pf.Preflight.FullScan || pf.Evaluation.Decision != types.DecisionRequireApproval {
			t.Fatalf("expected Easysearch match_all preflight escalation, got %+v err=%v", pf, err)
		}

		docWrite, err := svc.Execute(ctx, types.ExecRequest{
			TargetRefOrAlias: prodTgt.Alias,
			Query:            "POST /orders/_doc/9999\n{\"order_id\":9999,\"customer_email\":\"es@example.com\",\"amount_cents\":100,\"status\":\"paid\"}",
			Reason:           "Live Easysearch approval test",
			Wait:             false,
		})
		if err != nil || docWrite.Status != types.OpWaitingApproval {
			t.Fatalf("expected Easysearch write waiting_approval, got %+v err=%v", docWrite, err)
		}
		approvePendingHTTP(t, srv.WebURL(), docWrite.ApprovalID, docWrite.ApprovalURL, "approved easysearch")
		done := waitOpTerminal(t, ctx, svc, docWrite.OperationID)
		if done.Status != types.OpSucceeded {
			t.Fatalf("expected Easysearch approved write to succeed, got %+v", done)
		}
	})

	// ---- 13. SSH Tunnel ----
	sshHost := strings.TrimSpace(os.Getenv("AGENT_DBCTL_TEST_SSH_HOST"))
	if sshHost != "" {
		t.Run("SSHTunnel", func(t *testing.T) {
			keyPath := strings.TrimSpace(os.Getenv("AGENT_DBCTL_TEST_SSH_KEY"))
			if keyPath == "" {
				t.Skip("AGENT_DBCTL_TEST_SSH_KEY not set")
			}
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("read ssh key %s: %v", keyPath, err)
			}
			sshPort := 22
			if v := strings.TrimSpace(os.Getenv("AGENT_DBCTL_TEST_SSH_PORT")); v != "" {
				var p int
				if err := json.Unmarshal([]byte(v), &p); err == nil && p > 0 {
					sshPort = p
				}
			}
			sshUser := envOr("AGENT_DBCTL_TEST_SSH_USER", "root")
			sshCredID := seedCred("ssh-bastion-key", types.AccessReadWrite, sshUser, string(keyBytes))
			np, err := svc.Store().UpsertNetworkProfile(ctx, "live-test", types.NetworkProfile{
				Name:                "bastion-suzhou",
				Mode:                types.NetworkSSHTunnel,
				BastionHost:         sshHost,
				BastionPort:         sshPort,
				BastionUser:         sshUser,
				BastionCredentialID: sshCredID,
				SSHStrictHostKey:    false,
			})
			if err != nil {
				t.Fatalf("upsert ssh network profile: %v", err)
			}
			inst, err := svc.Store().UpsertInstance(ctx, "live-test", types.Instance{
				Name:             "live-pg-via-ssh",
				Engine:           "postgres",
				Host:             host,
				Port:             25432,
				Role:             types.RolePrimary,
				NetworkProfileID: np.ID,
			})
			if err != nil {
				t.Fatalf("upsert pg ssh instance: %v", err)
			}
			tgt, err := svc.Store().UpsertTarget(ctx, "live-test", types.Target{
				Ref:             "live-commerce/dev/pg-ssh",
				Alias:           "live-dev-pg-ssh",
				OwnerSystemID:   sys.ID,
				EnvironmentCode: "dev",
				InstanceID:      inst.ID,
				DatabaseName:    "orders_test",
				ROCredentialID:  pgRO,
				RWCredentialID:  pgRW,
			})
			if err != nil {
				t.Fatalf("upsert ssh target: %v", err)
			}
			res, err := svc.Execute(ctx, types.ExecRequest{
				TargetRefOrAlias: tgt.Alias,
				Query:            "SELECT id, status FROM orders WHERE id = 1 LIMIT 1",
				Wait:             true,
			})
			if err != nil || res.Status != types.OpSucceeded || len(res.Result.Rows) != 1 {
				t.Fatalf("SSH tunnel PG query failed: %+v err=%v", res, err)
			}
		})
	}

	verify, err := svc.Store().VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("audit chain verify failed after live tests: %+v err=%v", verify, err)
	}
}
