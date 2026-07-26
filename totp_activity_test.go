package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPEnableDisableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	store, err := openUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("admin", "password12", roleAdmin); err != nil {
		t.Fatal(err)
	}
	prev := users
	users = store
	t.Cleanup(func() { users = prev })

	if store.totpEnabled("admin") {
		t.Fatal("expected disabled")
	}
	secret := "JBSWY3DPEHPK3PXP"
	plain, hashes, err := generateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != totpRecoveryN {
		t.Fatalf("want %d codes", totpRecoveryN)
	}
	if err := store.enableTOTP("admin", secret, hashes); err != nil {
		t.Fatal(err)
	}
	if !store.totpEnabled("admin") {
		t.Fatal("expected enabled")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyTOTPOrRecovery("admin", code) {
		t.Fatal("TOTP code should validate")
	}
	if !verifyTOTPOrRecovery("admin", plain[0]) {
		t.Fatal("recovery code should validate")
	}
	if verifyTOTPOrRecovery("admin", plain[0]) {
		t.Fatal("recovery code should be single-use")
	}

	if err := store.disableTOTP("admin"); err != nil {
		t.Fatal(err)
	}
	if store.totpEnabled("admin") {
		t.Fatal("expected disabled after disable")
	}
}

func TestTOTPViewerRejected(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("friend", "password12", roleViewer); err != nil {
		t.Fatal(err)
	}
	if err := store.enableTOTP("friend", "JBSWY3DPEHPK3PXP", nil); err == nil {
		t.Fatal("viewer must not enable TOTP")
	}
}

func TestActivityLogPrivacyDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ACTIVITY_LOG", "")
	t.Setenv("ACTIVITY_LOG_IP", "")
	configureActivityLog(dir)
	if activityEnabled {
		t.Fatal("expected off by default")
	}
	auditLog("alice", "mkdir", "foo", nil)
	if _, err := os.Stat(filepath.Join(dir, "activity.jsonl")); !os.IsNotExist(err) {
		t.Fatal("must not write when disabled")
	}

	t.Setenv("ACTIVITY_LOG", "1")
	configureActivityLog(dir)
	if !activityEnabled {
		t.Fatal("expected enabled")
	}
	auditLog("alice", "mkdir", "foo/bar", nil)
	entries, err := readActivityRecent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].User != "alice" || entries[0].Action != "mkdir" || entries[0].Path != "foo/bar" {
		t.Fatalf("bad entry %+v", entries[0])
	}
	if entries[0].IP != "" {
		t.Fatal("IP must be empty unless ACTIVITY_LOG_IP=1")
	}

	t.Setenv("ACTIVITY_LOG_IP", "1")
	configureActivityLog(dir)
	r := &http.Request{RemoteAddr: "203.0.113.9:1234"}
	auditLog("bob", "delete", "x", r)
	entries, err = readActivityRecent(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.User == "bob" && e.IP == "203.0.113.9" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected IP on entry: %+v", entries)
	}
}
