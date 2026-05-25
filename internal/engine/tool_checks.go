package engine

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// Tool-check allowlists. Populated at startup via InitToolChecks; read by
// per-rule helpers below. Per-call mutation is not expected — the read path
// uses an RLock so it costs nothing under load.
var (
	toolChecksMu         sync.RWMutex
	cfgAllowedReadRoots  []string
	cfgAllowedWriteRoots []string
)

// InitToolChecks wires runtime config into the engine. Restricted-term
// state is shared with the PII redactor via InitRestrictedTerms so both
// the substring matcher (tool checks) and the word/domain regexes
// (PII redaction) stay derived from the same source list.
func InitToolChecks(restrictedTerms, allowedReadRoots, allowedWriteRoots []string) {
	InitRestrictedTerms(restrictedTerms)
	toolChecksMu.Lock()
	defer toolChecksMu.Unlock()
	cfgAllowedReadRoots = cleanRootList(allowedReadRoots)
	cfgAllowedWriteRoots = cleanRootList(allowedWriteRoots)
}

func cleanRootList(roots []string) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		r = strings.TrimRight(r, "/")
		if r == "" {
			r = "/"
		}
		out = append(out, r)
	}
	return out
}

func snapshotAllowedReadRoots() []string {
	toolChecksMu.RLock()
	defer toolChecksMu.RUnlock()
	return cfgAllowedReadRoots
}

func snapshotAllowedWriteRoots() []string {
	toolChecksMu.RLock()
	defer toolChecksMu.RUnlock()
	return cfgAllowedWriteRoots
}

// ---------------------------------------------------------------------------
// Static rule data
// ---------------------------------------------------------------------------

var (
	chmodSuidNumRE = regexp.MustCompile(`^4[0-7]{3}$`)

	urlHostRE = regexp.MustCompile(`(?i)\b(?:https?|ftp)://([^\s/?#"'\\]+)`)

	alwaysRemoteCommands = map[string]bool{
		"aws": true, "gcloud": true, "az": true, "kubectl": true,
		"gh": true, "hub": true,
		"terraform": true, "pulumi": true, "helm": true,
		"s3cmd": true, "gsutil": true, "rclone": true,
		"ping": true, "traceroute": true, "mtr": true,
		"nslookup": true, "dig": true, "host": true,
	}
	dockerRemoteSubs = map[string]bool{
		"pull": true, "push": true, "login": true,
	}
	publishCommands = map[string]map[string]bool{
		"npm":   {"publish": true},
		"cargo": {"publish": true},
		"gem":   {"push": true},
		"twine": {"upload": true},
	}

	sysConfigREs = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bsysctl\s+-w\b`),
		regexp.MustCompile(`(?i)\bsystemctl\s+(?:start|stop|restart|enable|disable)\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])service\s+\S+\s+(?:start|stop|restart)\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])hostname\s+\S+`),
		regexp.MustCompile(`(?i)\bhostnamectl\s+set-hostname\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])timedatectl\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])date\s+-s\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])iptables\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])ufw\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])firewall-cmd\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])ip\s+(?:link|route|addr)\s+(?:add|del|set)\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])route\s+(?:add|del)\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])mount(?:\s|$)`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])umount(?:\s|$)`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])useradd\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])userdel\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])usermod\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])groupadd\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])chsh\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])chfn\b`),
		regexp.MustCompile(`(?i)\bcrontab\s+-[er]\b`),
		regexp.MustCompile(`(?i)>>?\s*/etc/cron`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])modprobe\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])rmmod\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])insmod\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])setenforce\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])setsebool\b`),
		regexp.MustCompile(`(?i)\bupdate-grub\b`),
		regexp.MustCompile(`(?i)\bgrub-mkconfig\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])swapon\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])swapoff\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])kexec\b`),
		regexp.MustCompile(`(?i)\bupdate-alternatives\s+--set\b`),
	}

	destructiveFlatREs = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bmkfs\.\w+`),
		regexp.MustCompile(`(?i)\bwipefs\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])fdisk\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])parted\b`),
		regexp.MustCompile(`(?i)\bdd\s+.*\bof=/dev/(?:sd|nvme|hd|mmcblk|loop)`),
		regexp.MustCompile(`(?i)>\s*/dev/(?:sd|nvme|hd|mmcblk|loop)`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])shutdown\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])reboot\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])halt\b`),
		regexp.MustCompile(`(?i)(?:^|[\s;&|])poweroff\b`),
		regexp.MustCompile(`(?i)\binit\s+[06]\b`),
		regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:`),
	}

	dangerousAbsPrefixes = []string{
		"/etc", "/usr", "/var", "/bin", "/sbin",
		"/lib", "/lib64", "/boot", "/root", "/sys",
		"/proc", "/dev", "/opt", "/srv", "/home",
	}

	sensitiveFileREs = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^/etc/(?:passwd|shadow|sudoers)(?:/|$)`),
		regexp.MustCompile(`(?i)^~/\.(?:ssh|aws|kube|gnupg)(?:/|$)`),
		regexp.MustCompile(`(?i)(?:^|/)id_rsa(?:\.|$)`),
		regexp.MustCompile(`(?i)\.pem$`),
		regexp.MustCompile(`(?i)\.key$`),
		regexp.MustCompile(`(?i)^/root(?:/|$)`),
	}
	sensitiveBareNames = map[string]bool{
		".env":        true,
		"credentials": true,
	}

	pathTraversalRE = regexp.MustCompile(`(?:\.\./){3,}`)

	destructiveCmds = map[string]bool{
		"rm": true, "chmod": true, "chown": true, "mv": true, "cp": true,
	}

	readCmds = map[string]bool{
		"cat": true, "less": true, "more": true, "head": true, "tail": true,
		"bat": true, "xxd": true, "hexdump": true, "od": true,
		"strings": true, "file": true, "grep": true, "rg": true,
		"find": true, "ag": true, "ack": true,
		"awk": true, "sed": true, "wc": true, "diff": true,
		"vim": true, "vi": true, "nano": true, "emacs": true,
		"tar": true, "unzip": true, "7z": true,
	}

	readToolNames = map[string]bool{
		"read": true, "readfile": true, "read_file": true,
		"openfile": true, "open_file": true,
	}
	writeToolNames = map[string]bool{
		"write": true, "writefile": true, "write_file": true,
		"edit": true, "create": true,
	}

	writeRedirectRE = regexp.MustCompile(`>>?\s*(\S+)`)
)

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// CheckTools walks the LiteLLM tools/tool_calls JSON blobs, extracts strings
// (and decodes the JSON-encoded `arguments` string when present), and runs
// the security rules in priority order. Returns the first matching
// BlockKind and a labelled rule name; returns ("", "") on no match.
func CheckTools(rawTools, rawToolCalls json.RawMessage) (BlockKind, string) {
	var allStrings []string
	var fileOps []fileOp

	if len(rawTools) > 0 {
		var v any
		if err := json.Unmarshal(rawTools, &v); err == nil {
			walkStrings(v, &allStrings)
		}
	}
	if len(rawToolCalls) > 0 {
		var v any
		if err := json.Unmarshal(rawToolCalls, &v); err == nil {
			walkStrings(v, &allStrings)
			fileOps = extractFileOps(v)
		}
	}

	// Pass 1: rules 1-8 across all collected string fragments.
	for _, s := range allStrings {
		for _, seg := range splitSegments(s) {
			if k := evaluateSegment(seg); k != "" {
				return k, string(k)
			}
		}
	}

	// Pass 1b: rules 6-8 against tool-call file operations.
	for _, op := range fileOps {
		if k := evaluateFileOp(op); k != "" {
			return k, string(k)
		}
	}

	// Pass 2: RESTRICTED_TERM (lowest priority — runs only if nothing else matched).
	for _, s := range allStrings {
		if matchesRestrictedTerm(s) {
			return BlockRestrictedTerm, string(BlockRestrictedTerm)
		}
	}

	return "", ""
}

// ---------------------------------------------------------------------------
// Per-segment rule evaluation (rules 1-8 in priority order)
// ---------------------------------------------------------------------------

func evaluateSegment(seg string) BlockKind {
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return ""
	}
	tokens := tokenize(seg)

	if checkPrivilegeEscalation(seg, tokens) {
		return BlockPrivilegeEscalation
	}
	if checkRemoteGit(tokens) {
		return BlockRemoteGit
	}
	if checkExternalNetwork(seg, tokens) {
		return BlockExternalNetwork
	}

	// Rules 4-8: strip leading sudo (and its flags) so chained `sudo cmd ...`
	// parses against the same code path as bare `cmd ...`. Rule 1 already
	// fires on `sudo` itself; this strip is purely defensive.
	work := tokens
	if len(work) > 0 && strings.ToLower(work[0]) == "sudo" {
		work = work[1:]
		for len(work) > 0 && strings.HasPrefix(work[0], "-") {
			work = work[1:]
		}
	}

	if checkDestructive(seg, work) {
		return BlockDestructiveShell
	}
	if checkSystemConfig(seg) {
		return BlockSystemConfigChange
	}
	if checkSensitiveFileRead(work) {
		return BlockSensitiveFileRead
	}
	if checkExternalFileRead(work) {
		return BlockExternalFileRead
	}
	if checkExternalFileWrite(seg, work) {
		return BlockExternalFileWrite
	}
	return ""
}

// ---------------------------------------------------------------------------
// Rule 1: PRIVILEGE_ESCALATION
// ---------------------------------------------------------------------------

func checkPrivilegeEscalation(seg string, tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	cmd := strings.ToLower(tokens[0])
	switch cmd {
	case "sudo", "doas", "pkexec", "runuser", "su":
		return true
	case "passwd":
		return len(tokens) >= 2
	case "setcap", "setfacl":
		return true
	case "chmod":
		for _, t := range tokens[1:] {
			if t == "u+s" || chmodSuidNumRE.MatchString(t) {
				return true
			}
		}
	}
	// Also catch `chmod u+s` / `chmod 4xxx` mid-string (e.g. after a redirect).
	if strings.Contains(strings.ToLower(seg), "chmod ") {
		for _, t := range tokens {
			if t == "u+s" || chmodSuidNumRE.MatchString(t) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule 2: REMOTE_GIT
// ---------------------------------------------------------------------------

func checkRemoteGit(tokens []string) bool {
	if len(tokens) < 2 || strings.ToLower(tokens[0]) != "git" {
		return false
	}
	sub := strings.ToLower(tokens[1])
	switch sub {
	case "clone", "push":
		return true
	case "remote":
		if len(tokens) >= 3 {
			s2 := strings.ToLower(tokens[2])
			if s2 == "add" || s2 == "set-url" {
				return true
			}
		}
	case "submodule":
		if len(tokens) >= 3 && strings.ToLower(tokens[2]) == "add" {
			return true
		}
	case "archive":
		for _, t := range tokens[2:] {
			if t == "--remote" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule 3: EXTERNAL_NETWORK
// ---------------------------------------------------------------------------

func checkExternalNetwork(seg string, tokens []string) bool {
	for _, m := range urlHostRE.FindAllStringSubmatch(seg, -1) {
		if !isLocalhostHost(normalizeURLHost(m[1])) {
			return true
		}
	}
	if len(tokens) == 0 {
		return false
	}
	cmd := strings.ToLower(tokens[0])

	if alwaysRemoteCommands[cmd] {
		return true
	}

	if cmd == "docker" && len(tokens) >= 2 {
		if dockerRemoteSubs[strings.ToLower(tokens[1])] {
			return true
		}
	}
	if subs, ok := publishCommands[cmd]; ok && len(tokens) >= 2 {
		if subs[strings.ToLower(tokens[1])] {
			return true
		}
	}

	switch cmd {
	case "ssh", "scp", "sftp", "rsync", "sqlplus":
		// Prefer user@host pattern if any positional carries an @.
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if strings.Contains(t, "@") {
				return !isLocalhostHost(hostOnly(t))
			}
		}
		// Fallback for ssh-style: first non-flag positional is the host.
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			return !isLocalhostHost(hostOnly(t))
		}
	case "telnet", "ftp", "tftp", "mongo", "mongosh":
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			return !isLocalhostHost(hostOnly(t))
		}
	case "nc":
		// Listen mode (`-l` anywhere in the flags) → not an outbound call.
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") && strings.Contains(t, "l") {
				return false
			}
		}
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			return !isLocalhostHost(hostOnly(t))
		}
	case "psql", "mysql", "redis-cli":
		host := flagValue(tokens, "-h")
		if host == "" {
			return false
		}
		return !isLocalhostHost(host)
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule 4: DESTRUCTIVE_SHELL
// ---------------------------------------------------------------------------

func checkDestructive(seg string, tokens []string) bool {
	for _, re := range destructiveFlatREs {
		if re.MatchString(seg) {
			return true
		}
	}
	if len(tokens) == 0 {
		return false
	}
	cmd := strings.ToLower(tokens[0])
	if !destructiveCmds[cmd] {
		return false
	}
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if isDangerousPath(t) {
			return true
		}
	}
	return false
}

func isDangerousPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if p == "/" || p == "~" || p == "$HOME" {
		return true
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "$HOME/") {
		return true
	}
	for _, prefix := range dangerousAbsPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule 5: SYSTEM_CONFIG_CHANGE
// ---------------------------------------------------------------------------

func checkSystemConfig(seg string) bool {
	for _, re := range sysConfigREs {
		if re.MatchString(seg) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule 6: SENSITIVE_FILE_READ
// ---------------------------------------------------------------------------

func checkSensitiveFileRead(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	if !readCmds[strings.ToLower(tokens[0])] {
		return false
	}
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if isSensitivePath(t) {
			return true
		}
	}
	return false
}

func isSensitivePath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	candidates := []string{p, filepath.Clean(p)}
	for _, c := range candidates {
		for _, re := range sensitiveFileREs {
			if re.MatchString(c) {
				return true
			}
		}
	}
	base := filepath.Base(p)
	return sensitiveBareNames[base]
}

// ---------------------------------------------------------------------------
// Rule 7: EXTERNAL_FILE_READ
// ---------------------------------------------------------------------------

func checkExternalFileRead(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	if !readCmds[strings.ToLower(tokens[0])] {
		return false
	}
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if isExternalReadPath(t) {
			return true
		}
	}
	return false
}

func isExternalReadPath(p string) bool {
	if !isAbsoluteIsh(p) {
		return false
	}
	if pathTraversalRE.MatchString(p) {
		return true
	}
	return !underAllowedRoot(p, snapshotAllowedReadRoots())
}

// ---------------------------------------------------------------------------
// Rule 8: EXTERNAL_FILE_WRITE
// ---------------------------------------------------------------------------

func checkExternalFileWrite(seg string, tokens []string) bool {
	for _, m := range writeRedirectRE.FindAllStringSubmatch(seg, -1) {
		if isExternalWritePath(m[1]) {
			return true
		}
	}
	if len(tokens) == 0 {
		return false
	}
	cmd := strings.ToLower(tokens[0])
	switch cmd {
	case "tee":
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if isExternalWritePath(t) {
				return true
			}
		}
	case "sed":
		hasInPlace := false
		for _, t := range tokens[1:] {
			if t == "-i" || strings.HasPrefix(t, "-i") {
				hasInPlace = true
				break
			}
		}
		if hasInPlace {
			for _, t := range tokens[1:] {
				if strings.HasPrefix(t, "-") {
					continue
				}
				if isExternalWritePath(t) {
					return true
				}
			}
		}
	case "cp", "mv":
		var positionals []string
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			positionals = append(positionals, t)
		}
		if len(positionals) >= 2 {
			if isExternalWritePath(positionals[len(positionals)-1]) {
				return true
			}
		}
	}
	return false
}

func isExternalWritePath(p string) bool {
	if !isAbsoluteIsh(p) {
		return false
	}
	if pathTraversalRE.MatchString(p) {
		return true
	}
	return !underAllowedRoot(p, snapshotAllowedWriteRoots())
}

// ---------------------------------------------------------------------------
// Rule 9: RESTRICTED_TERM (case-insensitive substring against any string)
// ---------------------------------------------------------------------------

func matchesRestrictedTerm(s string) bool {
	for _, re := range snapshotRestrictedSubstrings() {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tool-call file-op evaluation (Read/Write/Edit/Create paths)
// ---------------------------------------------------------------------------

type fileOp struct {
	kind string // "read" or "write"
	path string
}

func evaluateFileOp(op fileOp) BlockKind {
	switch op.kind {
	case "read":
		if isSensitivePath(op.path) {
			return BlockSensitiveFileRead
		}
		if isExternalReadPath(op.path) {
			return BlockExternalFileRead
		}
	case "write":
		// Sensitive-write is captured by isExternalWritePath since
		// /etc/... etc. are not in the write allowlist either.
		if isExternalWritePath(op.path) {
			return BlockExternalFileWrite
		}
	}
	return ""
}

func extractFileOps(v any) []fileOp {
	var ops []fileOp
	arr, ok := v.([]any)
	if !ok {
		return ops
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		var name string
		var argsMap map[string]any

		if fn, ok := m["function"].(map[string]any); ok {
			name, _ = fn["name"].(string)
			switch a := fn["arguments"].(type) {
			case string:
				if a != "" {
					_ = json.Unmarshal([]byte(a), &argsMap)
				}
			case map[string]any:
				argsMap = a
			}
		}
		if name == "" {
			name, _ = m["name"].(string)
		}
		if argsMap == nil {
			if inp, ok := m["input"].(map[string]any); ok {
				argsMap = inp
			} else if a, ok := m["arguments"].(map[string]any); ok {
				argsMap = a
			} else if as, ok := m["arguments"].(string); ok && as != "" {
				_ = json.Unmarshal([]byte(as), &argsMap)
			}
		}
		if name == "" || argsMap == nil {
			continue
		}

		path, _ := argsMap["file_path"].(string)
		if path == "" {
			path, _ = argsMap["path"].(string)
		}
		if path == "" {
			continue
		}

		nameLower := strings.ToLower(name)
		switch {
		case readToolNames[nameLower]:
			ops = append(ops, fileOp{kind: "read", path: path})
		case writeToolNames[nameLower]:
			ops = append(ops, fileOp{kind: "write", path: path})
		}
	}
	return ops
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// walkStrings recursively walks a decoded JSON value and appends every
// string leaf. When it encounters an object key called "arguments" whose
// value is a string, it also decodes that string as JSON and recurses —
// this is how LiteLLM ships tool_call function.arguments.
func walkStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case []any:
		for _, item := range x {
			walkStrings(item, out)
		}
	case map[string]any:
		for k, item := range x {
			walkStrings(item, out)
			if k == "arguments" {
				if s, ok := item.(string); ok && s != "" {
					var inner any
					if err := json.Unmarshal([]byte(s), &inner); err == nil {
						walkStrings(inner, out)
					}
				}
			}
		}
	}
}

// splitSegments splits a shell-like string on `&&`, `||`, `;`, and `|`.
// Quoting is not respected — this is heuristic segmentation for rule
// dispatch, not a real shell parser.
func splitSegments(s string) []string {
	const sep = "\x00"
	r := strings.NewReplacer("&&", sep, "||", sep)
	s = r.Replace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == 0 || r == ';' || r == '|'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		t := strings.TrimSpace(s)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// tokenize splits on whitespace while honouring simple single- and
// double-quoted strings (with backslash escapes outside single quotes).
// Good enough for first-token command detection and positional scans.
func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble, escaped := false, false, false

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if unicode.IsSpace(r) && !inSingle && !inDouble {
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()
	return tokens
}

func isLocalhostHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0":
		return true
	}
	return false
}

func normalizeURLHost(raw string) string {
	if strings.HasPrefix(raw, "[") {
		if end := strings.Index(raw, "]"); end != -1 {
			return raw[1:end]
		}
		return raw
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		return raw[:i]
	}
	return raw
}

// hostOnly extracts the bare host from `user@host`, `host:port`, `host/path`
// formats. The `user@` prefix (if any) is stripped first.
func hostOnly(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func flagValue(tokens []string, flag string) string {
	for i := 1; i < len(tokens); i++ {
		if tokens[i] == flag && i+1 < len(tokens) {
			return tokens[i+1]
		}
		// Also support clustered form like `-hfoo`.
		if strings.HasPrefix(tokens[i], flag) && len(tokens[i]) > len(flag) {
			return tokens[i][len(flag):]
		}
	}
	return ""
}

func isAbsoluteIsh(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "$HOME")
}

func underAllowedRoot(p string, roots []string) bool {
	cleaned := filepath.Clean(p)
	for _, root := range roots {
		if cleaned == root || strings.HasPrefix(cleaned, root+"/") {
			return true
		}
	}
	return false
}
