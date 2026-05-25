package engine

import (
	"encoding/json"
	"os"
	"testing"
)

func setupToolChecks(t *testing.T) {
	t.Helper()
	InitToolChecks(
		[]string{"tsmc"},
		[]string{"/tmp", "/var/tmp", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"},
		[]string{"/tmp", "/var/tmp", "/dev/null", "/dev/stdout", "/dev/stderr"},
	)
}

// toolsBlob wraps a description string into the LiteLLM `tools` shape so
// the rule scanner has a realistic input.
func toolsBlob(desc string) json.RawMessage {
	type fn struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	type tool struct {
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	b, _ := json.Marshal([]tool{{Type: "function", Function: fn{Name: "shell", Description: desc}}})
	return b
}

func toolCallsBlob(name, argsJSON string) json.RawMessage {
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type call struct {
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}
	b, _ := json.Marshal([]call{{Type: "function", Function: fn{Name: name, Arguments: argsJSON}}})
	return b
}

// TestRuleMatrix is the central table — every rule has positive (block)
// and negative (allow) cases.
func TestRuleMatrix(t *testing.T) {
	setupToolChecks(t)

	cases := []struct {
		name string
		desc string // tool description = shell command to test
		want BlockKind
	}{
		// PRIVILEGE_ESCALATION — positives
		{"sudo apt", "sudo apt install foo", BlockPrivilegeEscalation},
		{"sudo -i", "sudo -i", BlockPrivilegeEscalation},
		{"su -", "su -", BlockPrivilegeEscalation},
		{"doas cmd", "doas systemctl restart nginx", BlockPrivilegeEscalation},
		{"chmod u+s", "chmod u+s ./bin", BlockPrivilegeEscalation},
		{"chmod 4755", "chmod 4755 /bin/sh", BlockPrivilegeEscalation},
		{"setcap", "setcap cap_net_raw+ep ./bin", BlockPrivilegeEscalation},
		{"passwd user", "passwd alice", BlockPrivilegeEscalation},
		// PRIVILEGE_ESCALATION — negatives
		{"chmod 755", "chmod 755 ./bin", ""},
		{"chmod 644", "chmod -R 644 ./config", ""},

		// REMOTE_GIT — positives
		{"git clone", "git clone https://github.com/x/y", BlockRemoteGit},
		{"git push", "git push origin main", BlockRemoteGit},
		{"git push force", "git push --force origin main", BlockRemoteGit},
		{"git remote add", "git remote add upstream foo", BlockRemoteGit},
		{"git submodule add", "git submodule add foo bar", BlockRemoteGit},
		// REMOTE_GIT — negatives
		{"git pull", "git pull origin main", ""},
		{"git fetch", "git fetch --all", ""},
		{"git commit", "git commit -m hello", ""},
		{"git diff", "git diff", ""},
		{"git checkout", "git checkout -b feat", ""},
		{"git submodule update", "git submodule update --init", ""},

		// EXTERNAL_NETWORK — positives
		{"curl github", "curl https://api.github.com/foo", BlockExternalNetwork},
		{"ssh user@host", "ssh user@github.com", BlockExternalNetwork},
		{"aws s3", "aws s3 ls", BlockExternalNetwork},
		{"kubectl", "kubectl get pods", BlockExternalNetwork},
		{"docker push", "docker push myimage", BlockExternalNetwork},
		{"npm publish", "npm publish", BlockExternalNetwork},
		{"psql remote", "psql -h db.example.com", BlockExternalNetwork},
		// EXTERNAL_NETWORK — negatives
		{"curl localhost", "curl http://localhost:8080/health", ""},
		{"curl 127", "curl http://127.0.0.1/x", ""},
		{"psql local", "psql -h localhost", ""},
		{"redis local ::1", "redis-cli -h ::1", ""},
		{"ssh localhost", "ssh user@localhost", ""},
		{"nc listen", "nc -l 9000", ""},

		// DESTRUCTIVE_SHELL — positives
		{"rm -rf /", "rm -rf /", BlockDestructiveShell},
		{"rm -rf /etc", "rm -rf /etc", BlockDestructiveShell},
		{"rm -rf $HOME", "rm -rf $HOME", BlockDestructiveShell},
		{"shutdown", "shutdown -h now", BlockDestructiveShell},
		{"mkfs", "mkfs.ext4 /dev/sda1", BlockDestructiveShell},
		{"dd to /dev/sda", "dd if=/dev/zero of=/dev/sda bs=1M", BlockDestructiveShell},
		// DESTRUCTIVE_SHELL — negatives
		{"rm file", "rm file.txt", ""},
		{"rm build", "rm -rf ./build", ""},
		{"rm node_modules", "rm -rf node_modules", ""},
		{"cp rel", "cp -r src/ backup/", ""},
		{"mv rel", "mv old.txt new.txt", ""},

		// SYSTEM_CONFIG_CHANGE — positives
		{"systemctl restart", "systemctl restart nginx", BlockSystemConfigChange},
		{"iptables", "iptables -A INPUT -j DROP", BlockSystemConfigChange},
		{"mount", "mount /dev/sda1 /mnt", BlockSystemConfigChange},
		{"useradd", "useradd attacker", BlockSystemConfigChange},
		{"crontab -e", "crontab -e", BlockSystemConfigChange},
		// SYSTEM_CONFIG_CHANGE — negatives
		{"make", "make", ""},
		{"go build", "go build ./...", ""},

		// SENSITIVE_FILE_READ — positives
		{"cat shadow", "cat /etc/shadow", BlockSensitiveFileRead},
		{"cat passwd", "cat /etc/passwd", BlockSensitiveFileRead},
		{"cat id_rsa", "cat ~/.ssh/id_rsa", BlockSensitiveFileRead},
		{"cat aws creds", "cat ~/.aws/credentials", BlockSensitiveFileRead},
		{"cat pem", "less server.pem", BlockSensitiveFileRead},
		// SENSITIVE_FILE_READ — negatives
		{"cat readme", "cat ./README.md", ""},
		{"cat tmp", "cat /tmp/scratch.json", ""},

		// EXTERNAL_FILE_READ — positives
		{"cat /home other", "cat /home/other/notes.txt", BlockExternalFileRead},
		{"cat escape", "cat /tmp/../etc/hosts", BlockExternalFileRead},
		{"find /etc", "find /etc -name '*.conf'", BlockExternalFileRead},
		// EXTERNAL_FILE_READ — negatives
		{"cat dev null", "cat /dev/null", ""},
		{"grep rel", "grep -r TODO ./internal", ""},
		{"find rel", "find . -name '*.go'", ""},

		// EXTERNAL_FILE_WRITE — positives
		{"redirect /etc", "echo x > /etc/hosts", BlockExternalFileWrite},
		{"tee /etc", "echo y | tee /etc/foo", BlockExternalFileWrite},
		// sed -i over /etc/hosts is caught by EXTERNAL_FILE_READ first (sed is
		// in the read-command set; priority 7 < 8).
		{"sed -i abs", "sed -i 's/a/b/' /etc/hosts", BlockExternalFileRead},
		{"tee abs no allow", "echo x | tee /var/log/foo", BlockExternalFileWrite},
		// EXTERNAL_FILE_WRITE — negatives
		{"redirect tmp", "echo x > /tmp/foo.log", ""},
		{"redirect rel", "echo y > out.txt", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := CheckTools(toolsBlob(tc.desc), nil)
			if got != tc.want {
				t.Fatalf("desc %q: got %q, want %q", tc.desc, got, tc.want)
			}
		})
	}
}

func TestRestrictedTermInDescription(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(toolsBlob("This tool talks to tsmc"), nil)
	if got != BlockRestrictedTerm {
		t.Fatalf("expected RESTRICTED_TERM, got %q", got)
	}
}

func TestRestrictedTermCaseInsensitive(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(toolsBlob("Description with TSMC inside"), nil)
	if got != BlockRestrictedTerm {
		t.Fatalf("expected RESTRICTED_TERM, got %q", got)
	}
}

func TestRestrictedTermClean(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(toolsBlob("Plain helpful description with no flagged terms"), nil)
	if got != "" {
		t.Fatalf("expected no block, got %q", got)
	}
}

func TestURLInArgumentJSON(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(nil, toolCallsBlob("fetch", `{"url":"https://example.com"}`))
	if got != BlockExternalNetwork {
		t.Fatalf("expected EXTERNAL_NETWORK, got %q", got)
	}
}

func TestWriteToolCallToAbsolutePath(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(nil, toolCallsBlob("Write", `{"file_path":"/home/other/x.txt"}`))
	if got != BlockExternalFileWrite {
		t.Fatalf("expected EXTERNAL_FILE_WRITE, got %q", got)
	}
}

func TestReadToolCallToRelativePath(t *testing.T) {
	setupToolChecks(t)
	cases := []string{"./src/x.go", "src/main.go", "go.mod"}
	for _, p := range cases {
		got, _ := CheckTools(nil, toolCallsBlob("Read", `{"file_path":"`+p+`"}`))
		if got != "" {
			t.Fatalf("expected pass for %q, got %q", p, got)
		}
	}
}

func TestEditToolCallToRelativePath(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(nil, toolCallsBlob("Edit", `{"file_path":"./go.mod"}`))
	if got != "" {
		t.Fatalf("expected pass, got %q", got)
	}
}

func TestWriteToolCallToRelativePath(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(nil, toolCallsBlob("Write", `{"file_path":"./src/main.go"}`))
	if got != "" {
		t.Fatalf("expected pass, got %q", got)
	}
}

func TestReadToolCallToSensitive(t *testing.T) {
	setupToolChecks(t)
	got, _ := CheckTools(nil, toolCallsBlob("Read", `{"file_path":"/etc/shadow"}`))
	if got != BlockSensitiveFileRead {
		t.Fatalf("expected SENSITIVE_FILE_READ, got %q", got)
	}
}

// Common safe scripting/build commands must all pass cleanly.
func TestMustPass_CommonDevCommands(t *testing.T) {
	setupToolChecks(t)
	commands := []string{
		"git pull origin main",
		"git fetch --all",
		"git commit -m \"x\"",
		"git diff",
		"git checkout -b feat",
		"npm install",
		"pip install -r requirements.txt",
		"go build ./...",
		"make",
		"rm -rf ./build",
		"rm -rf node_modules",
		"chmod 755 ./bin",
		"cat ./README.md",
		"grep -r TODO ./internal",
		"find . -name '*.go'",
		"psql -h localhost",
		"redis-cli -h ::1",
		"cat /tmp/scratch.json",
		"cat /dev/null",
	}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			if got, _ := CheckTools(toolsBlob(cmd), nil); got != "" {
				t.Fatalf("expected pass for %q, got %q", cmd, got)
			}
		})
	}
}

// Reasoned subset of must-block — caught by the highest-priority matching
// rule per the table above. Documented separately to mirror the task's
// must-BLOCK list.
func TestMustBlock_CoreCommands(t *testing.T) {
	setupToolChecks(t)
	cases := []struct {
		cmd  string
		want BlockKind
	}{
		{"sudo apt install foo", BlockPrivilegeEscalation},
		{"curl https://api.github.com/foo", BlockExternalNetwork},
		{"ssh user@github.com", BlockExternalNetwork},
		{"aws s3 ls", BlockExternalNetwork},
		{"rm -rf /", BlockDestructiveShell},
		{"systemctl restart nginx", BlockSystemConfigChange},
		{"git clone https://github.com/x/y", BlockRemoteGit},
		{"git push --force origin main", BlockRemoteGit},
		{"cat /etc/shadow", BlockSensitiveFileRead},
		{"cat ~/.ssh/id_rsa", BlockSensitiveFileRead},
		{"cat /home/other/notes.txt", BlockExternalFileRead},
		{"echo x > /etc/hosts", BlockExternalFileWrite},
		{"cat /tmp/../etc/hosts", BlockExternalFileRead},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			got, _ := CheckTools(toolsBlob(tc.cmd), nil)
			if got != tc.want {
				t.Fatalf("%q: got %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestBlockedReasonContainsRuleName(t *testing.T) {
	setupToolChecks(t)
	_, reason := CheckTools(toolsBlob("rm -rf /"), nil)
	if reason != string(BlockDestructiveShell) {
		t.Fatalf("reason mismatch: got %q want %q", reason, BlockDestructiveShell)
	}
}

func TestRestrictedTermShadowedByHigherPriority(t *testing.T) {
	setupToolChecks(t)
	// Description contains a restricted term *and* a separately-segmented
	// destructive command. The higher-priority rule (destructive shell) must
	// win — RESTRICTED_TERM is evaluated only after every other rule has
	// completed across all strings.
	got, _ := CheckTools(toolsBlob("tsmc note; rm -rf /"), nil)
	if got != BlockDestructiveShell {
		t.Fatalf("expected DESTRUCTIVE_SHELL (priority 4) to win over RESTRICTED_TERM, got %q", got)
	}
}

func TestSegmentationOnChainedCommands(t *testing.T) {
	setupToolChecks(t)
	// First segment is benign; second triggers a block. Each segment is
	// evaluated independently.
	got, _ := CheckTools(toolsBlob("echo ok && rm -rf /"), nil)
	if got != BlockDestructiveShell {
		t.Fatalf("expected DESTRUCTIVE_SHELL on chained segment, got %q", got)
	}
}

func TestEmptyBlobs(t *testing.T) {
	setupToolChecks(t)
	got, reason := CheckTools(nil, nil)
	if got != "" || reason != "" {
		t.Fatalf("expected no match on nil blobs, got %q / %q", got, reason)
	}
}

// Restore the default seed so other test files in the package aren't
// affected by allow-list mutation done here.
func TestMain(m *testing.M) {
	InitToolChecks(
		[]string{"tsmc"},
		[]string{"/tmp", "/var/tmp", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"},
		[]string{"/tmp", "/var/tmp", "/dev/null", "/dev/stdout", "/dev/stderr"},
	)
	os.Exit(m.Run())
}
