package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpPendingTTL   = 5 * time.Minute
	totpIssuer       = "dingbap"
	totpRecoveryN    = 8
	totpRecoveryLen  = 8 // bytes → hex chars
)

type pendingLogin struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

type pendingTOTPSetup struct {
	Secret    string
	ExpiresAt time.Time
}

var (
	totpMu       sync.Mutex
	pendingLogins = map[string]pendingLogin{}
	pendingSetups = map[string]pendingTOTPSetup{} // keyed by username
)

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(code))))
	return hex.EncodeToString(sum[:])
}

func newPendingToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func putPendingLogin(username, role string) (string, error) {
	tok, err := newPendingToken()
	if err != nil {
		return "", err
	}
	totpMu.Lock()
	defer totpMu.Unlock()
	now := time.Now()
	for k, v := range pendingLogins {
		if now.After(v.ExpiresAt) {
			delete(pendingLogins, k)
		}
	}
	pendingLogins[tok] = pendingLogin{
		Username:  username,
		Role:      role,
		ExpiresAt: now.Add(totpPendingTTL),
	}
	return tok, nil
}

func takePendingLogin(token string) (pendingLogin, bool) {
	totpMu.Lock()
	defer totpMu.Unlock()
	p, ok := pendingLogins[token]
	if !ok {
		return pendingLogin{}, false
	}
	delete(pendingLogins, token)
	if time.Now().After(p.ExpiresAt) {
		return pendingLogin{}, false
	}
	return p, true
}

func putPendingSetup(username, secret string) {
	totpMu.Lock()
	defer totpMu.Unlock()
	pendingSetups[strings.ToLower(username)] = pendingTOTPSetup{
		Secret:    secret,
		ExpiresAt: time.Now().Add(totpPendingTTL),
	}
}

func takePendingSetup(username string) (string, bool) {
	totpMu.Lock()
	defer totpMu.Unlock()
	key := strings.ToLower(username)
	p, ok := pendingSetups[key]
	if !ok {
		return "", false
	}
	delete(pendingSetups, key)
	if time.Now().After(p.ExpiresAt) {
		return "", false
	}
	return p.Secret, true
}

func peekPendingSetup(username string) (string, bool) {
	totpMu.Lock()
	defer totpMu.Unlock()
	p, ok := pendingSetups[strings.ToLower(username)]
	if !ok || time.Now().After(p.ExpiresAt) {
		return "", false
	}
	return p.Secret, true
}

func generateRecoveryCodes() (plain []string, hashes []string, err error) {
	plain = make([]string, totpRecoveryN)
	hashes = make([]string, totpRecoveryN)
	for i := 0; i < totpRecoveryN; i++ {
		b := make([]byte, totpRecoveryLen)
		if _, err = rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := hex.EncodeToString(b)
		plain[i] = code
		hashes[i] = hashRecoveryCode(code)
	}
	return plain, hashes, nil
}

func verifyTOTPOrRecovery(username, code string) bool {
	secret, _, ok := users.totpSecret(username)
	if !ok {
		return false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	if totp.Validate(code, secret) {
		return true
	}
	if len(code) >= 12 {
		return users.consumeRecoveryCode(username, code)
	}
	return false
}

// finishLoginAfterPassword is called once password auth succeeds.
// If admin TOTP is enabled, returns a pending token instead of a session.
func finishLoginAfterPassword(w http.ResponseWriter, r *http.Request, ip string, user *User) {
	if user.Role == roleAdmin && users.totpEnabled(user.Username) {
		tok, err := putPendingLogin(user.Username, user.Role)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "Failed to start 2FA step")
			return
		}
		sessions.clearFailures(ip)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"totp_required": true,
			"pending_token": tok,
		})
		return
	}
	id, err := sessions.create(user.Username, user.Role)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	sessions.clearFailures(ip)
	sessions.setCookie(w, id)
	auditLog(user.Username, "login", "", r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": user.Username,
		"role":     user.Role,
	})
}

func handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if !sameOrigin(r) {
		jsonErr(w, http.StatusForbidden, "Invalid origin")
		return
	}
	ip := clientIP(r)
	if !sessions.allowLogin(ip) {
		jsonErr(w, http.StatusTooManyRequests, "Too many failed attempts — try again in a minute")
		return
	}
	var body struct {
		PendingToken string `json:"pending_token"`
		Code         string `json:"code"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	pending, ok := takePendingLogin(body.PendingToken)
	if !ok {
		sessions.recordFailure(ip)
		jsonErr(w, http.StatusUnauthorized, "2FA session expired — sign in again")
		return
	}
	if !verifyTOTPOrRecovery(pending.Username, body.Code) {
		// Re-queue a short window so one typo doesn't force full re-login,
		// but still count toward rate limit.
		sessions.recordFailure(ip)
		if tok, err := putPendingLogin(pending.Username, pending.Role); err == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":            false,
				"error":         "Invalid authenticator code",
				"totp_required": true,
				"pending_token": tok,
			})
			return
		}
		jsonErr(w, http.StatusUnauthorized, "Invalid authenticator code")
		return
	}
	id, err := sessions.create(pending.Username, pending.Role)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	sessions.clearFailures(ip)
	sessions.setCookie(w, id)
	auditLog(pending.Username, "login", "", r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": pending.Username,
		"role":     pending.Role,
	})
}

func handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	s := sessionFromCtx(r)
	if s == nil {
		jsonErr(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	enabled := s.Role == roleAdmin && users.totpEnabled(s.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"enabled": enabled,
		"admin":   s.Role == roleAdmin,
	})
}

func handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s := sessionFromCtx(r)
	if s == nil || s.Role != roleAdmin {
		jsonErr(w, http.StatusForbidden, "Admin only")
		return
	}
	if users.totpEnabled(s.Username) {
		jsonErr(w, http.StatusConflict, "Two-factor authentication is already enabled")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: s.Username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to generate authenticator secret")
		return
	}
	putPendingSetup(s.Username, key.Secret())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"secret": key.Secret(),
		"uri":    key.URL(),
	})
}

func handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s := sessionFromCtx(r)
	if s == nil || s.Role != roleAdmin {
		jsonErr(w, http.StatusForbidden, "Admin only")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	secret, ok := peekPendingSetup(s.Username)
	if !ok {
		jsonErr(w, http.StatusBadRequest, "No setup in progress — start again")
		return
	}
	if !totp.Validate(strings.TrimSpace(body.Code), secret) {
		jsonErr(w, http.StatusBadRequest, "Invalid authenticator code")
		return
	}
	secret, ok = takePendingSetup(s.Username)
	if !ok {
		jsonErr(w, http.StatusBadRequest, "Setup expired — start again")
		return
	}
	plain, hashes, err := generateRecoveryCodes()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to create recovery codes")
		return
	}
	if err := users.enableTOTP(s.Username, secret, hashes); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	auditLog(s.Username, "totp_enable", "", r)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"message":        "Two-factor authentication enabled",
		"recovery_codes": plain,
	})
}

func handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s := sessionFromCtx(r)
	if s == nil || s.Role != roleAdmin {
		jsonErr(w, http.StatusForbidden, "Admin only")
		return
	}
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if _, err := users.authenticate(s.Username, body.Password); err != nil {
		jsonErr(w, http.StatusUnauthorized, "Invalid password")
		return
	}
	if users.totpEnabled(s.Username) {
		if !verifyTOTPOrRecovery(s.Username, body.Code) {
			jsonErr(w, http.StatusUnauthorized, "Invalid authenticator or recovery code")
			return
		}
	}
	if err := users.disableTOTP(s.Username); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	auditLog(s.Username, "totp_disable", "", r)
	jsonOK(w, "Two-factor authentication disabled")
}