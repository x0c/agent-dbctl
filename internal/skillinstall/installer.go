package skillinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
)

const (
	// SkillName is the directory name installed under each agent runtime's skill root.
	SkillName      = "agent-dbctl"
	skillFileName  = "SKILL.md"
	lockStaleAfter = 30 * time.Second
)

// RuntimeRoot describes a candidate skill root directory for a coding-agent runtime.
type RuntimeRoot struct {
	Runtime      string `json:"runtime"`
	Root         string `json:"root"`
	ResolvedRoot string `json:"resolved_root"`
	Available    bool   `json:"available"`
	RootExists   bool   `json:"root_exists"`
}

// TargetGroup merges runtimes whose skill roots resolve to the same physical directory.
type TargetGroup struct {
	ResolvedRoot string   `json:"resolved_root"`
	Runtimes     []string `json:"runtimes"`
	Roots        []string `json:"roots"`
}

// ActionItem reports the status or outcome of installing/removing the skill in one physical target.
type ActionItem struct {
	Skill    string   `json:"skill"`
	Path     string   `json:"path"`
	Runtimes []string `json:"runtimes"`
	Action   string   `json:"action"`
	State    string   `json:"state"`
	Hint     string   `json:"hint,omitempty"`
}

// InstallOpts configures Install behavior.
type InstallOpts struct {
	DryRun        bool
	Force         bool
	Runtime       string
	Version       string
	SkillMarkdown string
}

// InstallResult summarizes install, update, or uninstall actions.
type InstallResult struct {
	DryRun        bool         `json:"dry_run"`
	Status        string       `json:"status"`
	BundleVersion string       `json:"bundle_version,omitempty"`
	BundleHash    string       `json:"bundle_hash,omitempty"`
	ManifestPath  string       `json:"manifest_path"`
	Actions       []ActionItem `json:"actions"`
	Conflicts     []ActionItem `json:"conflicts,omitempty"`
}

// StatusResult summarizes current companion skill state across detected agent runtimes.
type StatusResult struct {
	BundleVersion string        `json:"bundle_version"`
	BundleHash    string        `json:"bundle_hash"`
	ManifestPath  string        `json:"manifest_path"`
	Runtimes      []RuntimeRoot `json:"runtimes"`
	Targets       []ActionItem  `json:"targets"`
}

type manifestRecord struct {
	Skill       string  `json:"skill"`
	Hash        string  `json:"hash"`
	PendingHash string  `json:"pending_hash,omitempty"`
	Version     string  `json:"version,omitempty"`
	UpdatedAt   float64 `json:"updated_at"`
}

type manifest struct {
	BundleVersion string                    `json:"bundle_version"`
	BundleHash    string                    `json:"bundle_hash"`
	TargetsDigest string                    `json:"targets_digest"`
	CheckedAt     float64                   `json:"checked_at"`
	HasConflicts  bool                      `json:"has_conflicts,omitempty"`
	Installed     map[string]manifestRecord `json:"installed"`
}

func contentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:24]
}

// DetectRuntimeRoots inspects supported local coding-agent skill directories without mutating disk.
func DetectRuntimeRoots() ([]RuntimeRoot, error) {
	if custom := strings.TrimSpace(os.Getenv(config.EnvSkillHome)); custom != "" {
		abs, err := filepath.Abs(custom)
		if err != nil {
			return nil, err
		}
		resolved := resolveSymlinkPath(abs)
		return []RuntimeRoot{{
			Runtime:      "custom",
			Root:         abs,
			ResolvedRoot: resolved,
			Available:    true,
			RootExists:   isDir(resolved),
		}}, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user home: %w", err)
	}
	xdgConfig := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}

	shared := filepath.Join(home, ".agents", "skills")
	sharedExists := isDir(shared)

	type candidate struct {
		name      string
		root      string
		baseDir   string
		cliBinary string
		useShared bool
	}

	claudeBase := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR"))
	if claudeBase == "" {
		claudeBase = filepath.Join(home, ".claude")
	}
	codexBase := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codexBase == "" {
		codexBase = filepath.Join(home, ".codex")
	}
	piBase := strings.TrimSpace(os.Getenv("PI_CODING_AGENT_DIR"))
	if piBase == "" {
		piBase = filepath.Join(home, ".pi", "agent")
	}
	agBase := strings.TrimSpace(os.Getenv("ANTIGRAVITY_APP_DATA_DIR"))
	if agBase == "" {
		agBase = filepath.Join(home, ".gemini", "antigravity-cli")
	}
	openCodeBase := filepath.Join(xdgConfig, "opencode")
	cursorBase := filepath.Join(home, ".cursor")
	agentsBase := filepath.Join(home, ".agents")

	candidates := []candidate{
		{name: "claude", root: filepath.Join(claudeBase, "skills"), baseDir: claudeBase, cliBinary: "claude"},
		{name: "codex", root: filepath.Join(codexBase, "skills"), baseDir: codexBase, cliBinary: "codex", useShared: true},
		{name: "opencode", root: filepath.Join(openCodeBase, "skills"), baseDir: openCodeBase, cliBinary: "opencode"},
		{name: "cursor", root: filepath.Join(cursorBase, "skills"), baseDir: cursorBase, cliBinary: "cursor"},
		{name: "pi", root: filepath.Join(piBase, "skills"), baseDir: piBase, cliBinary: "pi", useShared: true},
		{name: "antigravity", root: filepath.Join(agBase, "skills"), baseDir: agBase, cliBinary: "agy"},
		{name: "agents", root: shared, baseDir: agentsBase},
	}

	out := make([]RuntimeRoot, 0, len(candidates))
	needPathLookup := make([]int, 0, len(candidates))
	for i, c := range candidates {
		root := c.root
		avail := isDir(c.baseDir) || isDir(root)
		if c.useShared && sharedExists {
			root = shared
			avail = true
		}
		if !avail && c.cliBinary != "" {
			needPathLookup = append(needPathLookup, i)
		}
		out = append(out, RuntimeRoot{
			Runtime:   c.name,
			Root:      root,
			Available: avail,
		})
	}
	if len(needPathLookup) > 0 {
		needed := make(map[string]int, len(needPathLookup))
		for _, idx := range needPathLookup {
			needed[candidates[idx].cliBinary] = idx
		}
		for _, idx := range findBinariesInPath(needed) {
			out[idx].Available = true
		}
	}
	for i := range out {
		resolved := resolveSymlinkPath(out[i].Root)
		out[i].ResolvedRoot = resolved
		out[i].RootExists = isDir(resolved)
	}
	return out, nil
}

func findBinariesInPath(needed map[string]int) []int {
	if len(needed) == 0 {
		return nil
	}
	// On Windows or non-standard PATHEXT setups, delegate to exec.LookPath per missing binary.
	if os.Getenv("PATHEXT") != "" {
		var found []int
		for bin, idx := range needed {
			if _, err := exec.LookPath(bin); err == nil {
				found = append(found, idx)
			}
		}
		return found
	}
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}
	var found []int
	remaining := len(needed)
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			dir = "."
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			idx, want := needed[e.Name()]
			if !want {
				continue
			}
			info, err := os.Stat(filepath.Join(dir, e.Name()))
			if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
				continue
			}
			found = append(found, idx)
			delete(needed, e.Name())
			remaining--
			if remaining == 0 {
				return found
			}
		}
	}
	return found
}

// resolveSymlinkPath resolves symlinks even if trailing path segments do not yet exist.
func resolveSymlinkPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if realPath, err := filepath.EvalSymlinks(abs); err == nil {
		return realPath
	}
	cur := abs
	var tail []string
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		if realParent, err := filepath.EvalSymlinks(parent); err == nil {
			parts := append([]string{realParent}, tail...)
			return filepath.Join(parts...)
		}
		cur = parent
	}
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func isSymlink(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func deduplicateTargets(roots []RuntimeRoot, filterRuntime string) []TargetGroup {
	idxByResolved := map[string]int{}
	var groups []TargetGroup
	for _, r := range roots {
		if filterRuntime != "" && r.Runtime != filterRuntime {
			continue
		}
		if !r.Available {
			continue
		}
		if idx, ok := idxByResolved[r.ResolvedRoot]; ok {
			groups[idx].Runtimes = append(groups[idx].Runtimes, r.Runtime)
			groups[idx].Roots = append(groups[idx].Roots, r.Root)
			continue
		}
		idxByResolved[r.ResolvedRoot] = len(groups)
		groups = append(groups, TargetGroup{
			ResolvedRoot: r.ResolvedRoot,
			Runtimes:     []string{r.Runtime},
			Roots:        []string{r.Root},
		})
	}
	return groups
}

func targetsDigest(roots []RuntimeRoot) string {
	h := sha256.New()
	for _, r := range roots {
		_, _ = h.Write([]byte(r.Runtime))
		_, _ = h.Write([]byte{'|'})
		_, _ = h.Write([]byte(r.Root))
		_, _ = h.Write([]byte{'|'})
		_, _ = h.Write([]byte(r.ResolvedRoot))
		_, _ = h.Write([]byte{'|'})
		if r.Available {
			_, _ = h.Write([]byte{'1'})
		} else {
			_, _ = h.Write([]byte{'0'})
		}
		if r.RootExists {
			_, _ = h.Write([]byte{'1'})
		} else {
			_, _ = h.Write([]byte{'0'})
		}
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func manifestFilePath() (string, error) {
	home, err := config.ResolveConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "skills", "registrations.json"), nil
}

func loadManifest(path string) manifest {
	m := manifest{Installed: map[string]manifestRecord{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return manifest{Installed: map[string]manifestRecord{}}
	}
	if m.Installed == nil {
		m.Installed = map[string]manifestRecord{}
	}
	return m
}

func saveManifest(path string, m manifest) error {
	dir := filepath.Dir(path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(dir, ".registrations.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func withLock(manifestPath string, fn func() error) error {
	dir := filepath.Dir(manifestPath)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "registrations.lock")
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			defer func() { _ = os.Remove(lockPath) }()
			return fn()
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > lockStaleAfter {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acquire skill sync lock %s: %w", lockPath, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func inspectState(skillDir, bundleHash string, m manifest) string {
	targetFile := filepath.Join(skillDir, skillFileName)
	if isSymlink(skillDir) || isSymlink(targetFile) {
		return "conflict"
	}
	info, err := os.Lstat(skillDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing"
		}
		return "conflict"
	}
	if !info.IsDir() {
		return "conflict"
	}
	rec, owned := m.Installed[skillDir]
	if !owned {
		return "conflict"
	}
	raw, err := os.ReadFile(targetFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing"
		}
		return "conflict"
	}
	cur := contentHash(string(raw))
	if cur != rec.Hash && (rec.PendingHash == "" || cur != rec.PendingHash) {
		return "modified"
	}
	if cur == bundleHash {
		return "current"
	}
	return "outdated"
}

func writeSkillFile(skillDir, content string) error {
	if isSymlink(skillDir) {
		return fmt.Errorf("refusing symlinked skill directory %s", skillDir)
	}
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return err
	}
	targetFile := filepath.Join(skillDir, skillFileName)
	if isSymlink(targetFile) {
		return fmt.Errorf("refusing symlinked skill file %s", targetFile)
	}
	tmp, err := os.CreateTemp(skillDir, ".SKILL.agent-dbctl-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// os.Rename replaces the directory entry atomically, avoiding hardlink write-through on Windows.
	if err := os.Rename(tmpName, targetFile); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// Status reports current companion skill installation state across detected coding agents.
func Status(version, skillMarkdown, filterRuntime string) (StatusResult, error) {
	roots, err := DetectRuntimeRoots()
	if err != nil {
		return StatusResult{}, err
	}
	mPath, err := manifestFilePath()
	if err != nil {
		return StatusResult{}, err
	}
	bHash := contentHash(skillMarkdown)
	m := loadManifest(mPath)
	groups := deduplicateTargets(roots, filterRuntime)

	var filteredRoots []RuntimeRoot
	for _, r := range roots {
		if filterRuntime == "" || r.Runtime == filterRuntime {
			filteredRoots = append(filteredRoots, r)
		}
	}

	targets := make([]ActionItem, 0, len(groups))
	for _, g := range groups {
		skillDir := filepath.Join(g.ResolvedRoot, SkillName)
		st := inspectState(skillDir, bHash, m)
		targets = append(targets, ActionItem{
			Skill:    SkillName,
			Path:     skillDir,
			Runtimes: g.Runtimes,
			Action:   "status",
			State:    st,
		})
	}
	return StatusResult{
		BundleVersion: version,
		BundleHash:    bHash,
		ManifestPath:  mPath,
		Runtimes:      filteredRoots,
		Targets:       targets,
	}, nil
}

// Install installs or updates the embedded SKILL.md into detected coding-agent skill roots.
func Install(opts InstallOpts) (InstallResult, error) {
	if strings.TrimSpace(opts.SkillMarkdown) == "" {
		return InstallResult{}, fmt.Errorf("embedded SKILL.md payload is empty")
	}
	roots, err := DetectRuntimeRoots()
	if err != nil {
		return InstallResult{}, err
	}
	mPath, err := manifestFilePath()
	if err != nil {
		return InstallResult{}, err
	}

	var result InstallResult
	run := func() error {
		bHash := contentHash(opts.SkillMarkdown)
		m := loadManifest(mPath)
		groups := deduplicateTargets(roots, opts.Runtime)
		actions := make([]ActionItem, 0, len(groups))
		var conflicts []ActionItem
		now := float64(time.Now().Unix())
		changed := false

		for _, g := range groups {
			skillDir := filepath.Join(g.ResolvedRoot, SkillName)
			state := inspectState(skillDir, bHash, m)
			action := "conflict"
			switch state {
			case "missing":
				action = "create"
			case "outdated":
				action = "update"
			case "current":
				action = "unchanged"
			case "conflict", "modified":
				if opts.Force && !isSymlink(skillDir) && !isSymlink(filepath.Join(skillDir, skillFileName)) {
					action = "overwrite"
				}
			}

			item := ActionItem{
				Skill:    SkillName,
				Path:     skillDir,
				Runtimes: g.Runtimes,
				Action:   action,
				State:    state,
			}
			if action == "conflict" {
				item.Hint = "Preserved existing or symlinked SKILL.md not owned by agent-dbctl; pass --force to replace regular files."
				conflicts = append(conflicts, item)
				actions = append(actions, item)
				continue
			}

			if action != "unchanged" {
				changed = true
				if !opts.DryRun {
					m.Installed[skillDir] = manifestRecord{
						Skill:       SkillName,
						Hash:        m.Installed[skillDir].Hash,
						PendingHash: bHash,
						Version:     opts.Version,
						UpdatedAt:   now,
					}
					if err := saveManifest(mPath, m); err != nil {
						return err
					}
					if err := writeSkillFile(skillDir, opts.SkillMarkdown); err != nil {
						return err
					}
				}
			}
			if !opts.DryRun {
				m.Installed[skillDir] = manifestRecord{
					Skill:     SkillName,
					Hash:      bHash,
					Version:   opts.Version,
					UpdatedAt: now,
				}
			}
			actions = append(actions, item)
		}

		if !opts.DryRun {
			m.BundleVersion = opts.Version
			m.BundleHash = bHash
			m.TargetsDigest = targetsDigest(roots)
			m.CheckedAt = now
			m.HasConflicts = len(conflicts) > 0
			if err := saveManifest(mPath, m); err != nil {
				return err
			}
		}

		status := "unchanged"
		if opts.DryRun {
			status = "planned"
		} else if changed {
			status = "applied"
		}
		result = InstallResult{
			DryRun:        opts.DryRun,
			Status:        status,
			BundleVersion: opts.Version,
			BundleHash:    bHash,
			ManifestPath:  mPath,
			Actions:       actions,
			Conflicts:     conflicts,
		}
		return nil
	}

	if opts.DryRun {
		if err := run(); err != nil {
			return InstallResult{}, err
		}
		return result, nil
	}
	if err := withLock(mPath, run); err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

// Uninstall removes agent-dbctl-owned SKILL.md copies while leaving user-modified or foreign files intact.
func Uninstall(dryRun bool, filterRuntime, skillMarkdown string) (InstallResult, error) {
	roots, err := DetectRuntimeRoots()
	if err != nil {
		return InstallResult{}, err
	}
	mPath, err := manifestFilePath()
	if err != nil {
		return InstallResult{}, err
	}

	var result InstallResult
	run := func() error {
		bHash := contentHash(skillMarkdown)
		m := loadManifest(mPath)
		groups := deduplicateTargets(roots, "")
		allowedByDir := map[string][]string{}
		for _, g := range groups {
			dir := filepath.Join(g.ResolvedRoot, SkillName)
			if filterRuntime != "" && !containsString(g.Runtimes, filterRuntime) {
				continue
			}
			allowedByDir[dir] = g.Runtimes
		}

		paths := make([]string, 0, len(m.Installed))
		for p := range m.Installed {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		actions := make([]ActionItem, 0, len(paths))
		changed := false
		for _, skillDir := range paths {
			runtimes, ok := allowedByDir[skillDir]
			if filterRuntime != "" && !ok {
				continue
			}
			state := inspectState(skillDir, bHash, m)
			action := "keep_modified"
			switch state {
			case "current", "outdated":
				action = "remove"
				changed = true
			case "missing":
				action = "forget"
				changed = true
			}
			item := ActionItem{
				Skill:    SkillName,
				Path:     skillDir,
				Runtimes: runtimes,
				Action:   action,
				State:    state,
			}
			if !dryRun && (action == "remove" || action == "forget") {
				if action == "remove" {
					_ = os.Remove(filepath.Join(skillDir, skillFileName))
					if entries, readErr := os.ReadDir(skillDir); readErr == nil && len(entries) == 0 {
						_ = os.Remove(skillDir)
					}
				}
				delete(m.Installed, skillDir)
			}
			actions = append(actions, item)
		}

		if !dryRun {
			m.BundleHash = ""
			m.TargetsDigest = ""
			if err := saveManifest(mPath, m); err != nil {
				return err
			}
		}
		status := "unchanged"
		if dryRun {
			status = "planned"
		} else if changed {
			status = "applied"
		}
		result = InstallResult{
			DryRun:       dryRun,
			Status:       status,
			ManifestPath: mPath,
			Actions:      actions,
		}
		return nil
	}

	if dryRun {
		if err := run(); err != nil {
			return InstallResult{}, err
		}
		return result, nil
	}
	if err := withLock(mPath, run); err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

// AutoSync quietly installs or updates the companion SKILL.md on CLI runs without touching stdout or stderr.
func AutoSync(version, skillMarkdown string) {
	if isTruthy(os.Getenv(config.EnvNoSkillSync)) || isFalsy(os.Getenv(config.EnvSkillsAuto)) {
		return
	}
	if strings.TrimSpace(os.Getenv(config.EnvSkillHome)) == "" && isTruthy(os.Getenv("CI")) {
		return
	}
	if strings.TrimSpace(skillMarkdown) == "" {
		return
	}

	roots, err := DetectRuntimeRoots()
	if err != nil {
		return
	}
	mPath, err := manifestFilePath()
	if err != nil {
		return
	}
	bHash := contentHash(skillMarkdown)
	tDigest := targetsDigest(roots)
	m := loadManifest(mPath)

	if m.BundleHash == bHash && m.TargetsDigest == tDigest {
		if !m.HasConflicts {
			return
		}
		if time.Since(time.Unix(int64(m.CheckedAt), 0)) < 60*time.Second {
			return
		}
	}

	_, _ = Install(InstallOpts{
		DryRun:        false,
		Force:         false,
		Version:       version,
		SkillMarkdown: skillMarkdown,
	})
}

func containsString(items []string, target string) bool {
	for _, it := range items {
		if it == target {
			return true
		}
	}
	return false
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isFalsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}
