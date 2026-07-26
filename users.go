package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	roleAdmin  = "admin"
	roleViewer = "viewer"
)

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Role         string   `json:"role"`
	// Optional admin TOTP (secrets stay in users.json on disk; never sent to third parties).
	TOTPSecret       string   `json:"totp_secret,omitempty"`
	TOTPEnabled      bool     `json:"totp_enabled,omitempty"`
	TOTPRecoveryHash []string `json:"totp_recovery_hashes,omitempty"`
}

type userStore struct {
	mu    sync.RWMutex
	path  string
	Users []User `json:"users"`
}

func openUserStore(path string) (*userStore, error) {
	s := &userStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	return s, nil
}

func (s *userStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Users []User `json:"users"`
	}{Users: s.Users}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0600)
}

func (s *userStore) empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Users) == 0
}

func (s *userStore) addUser(username, password, role string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password required")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if role != roleAdmin && role != roleViewer {
		return errors.New("role must be admin or viewer")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if strings.EqualFold(u.Username, username) {
			return fmt.Errorf("user %q already exists", username)
		}
	}
	s.Users = append(s.Users, User{Username: username, PasswordHash: hash, Role: role})
	return s.save()
}

func (s *userStore) authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.Users {
		u := &s.Users[i]
		if !strings.EqualFold(u.Username, username) {
			continue
		}
		ok, err := verifyPassword(u.PasswordHash, password)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errInvalidCredentials
		}
		cp := *u
		return &cp, nil
	}
	// Unknown username: still run a full Argon2 verify against a dummy hash so
	// response timing does not reveal whether the account exists.
	_, _ = verifyPassword(dummyPasswordHash(), password)
	return nil, errInvalidCredentials
}

func (s *userStore) byUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.Users {
		if strings.EqualFold(s.Users[i].Username, username) {
			cp := s.Users[i]
			return &cp, true
		}
	}
	return nil, false
}

// listPublic returns users without password hashes (for admin UI).
func (s *userStore) listPublic() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, len(s.Users))
	for i, u := range s.Users {
		out[i] = User{
			Username:    u.Username,
			Role:        u.Role,
			TOTPEnabled: u.TOTPEnabled && u.TOTPSecret != "",
		}
	}
	return out
}

func (s *userStore) adminCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, u := range s.Users {
		if u.Role == roleAdmin {
			n++
		}
	}
	return n
}

func (s *userStore) setPassword(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password required")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if strings.EqualFold(s.Users[i].Username, username) {
			s.Users[i].PasswordHash = hash
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *userStore) setRole(username, role string) error {
	username = strings.TrimSpace(username)
	if role != roleAdmin && role != roleViewer {
		return errors.New("role must be admin or viewer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.Users {
		if strings.EqualFold(s.Users[i].Username, username) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("user %q not found", username)
	}
	if s.Users[idx].Role == roleAdmin && role != roleAdmin {
		admins := 0
		for _, u := range s.Users {
			if u.Role == roleAdmin {
				admins++
			}
		}
		if admins <= 1 {
			return errors.New("cannot demote the last admin")
		}
	}
	s.Users[idx].Role = role
	if role != roleAdmin {
		s.Users[idx].TOTPSecret = ""
		s.Users[idx].TOTPEnabled = false
		s.Users[idx].TOTPRecoveryHash = nil
	}
	return s.save()
}

func (s *userStore) deleteUser(username string) error {
	username = strings.TrimSpace(username)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.Users {
		if strings.EqualFold(s.Users[i].Username, username) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("user %q not found", username)
	}
	if s.Users[idx].Role == roleAdmin {
		admins := 0
		for _, u := range s.Users {
			if u.Role == roleAdmin {
				admins++
			}
		}
		if admins <= 1 {
			return errors.New("cannot delete the last admin")
		}
	}
	s.Users = append(s.Users[:idx], s.Users[idx+1:]...)
	return s.save()
}

func (s *userStore) totpEnabled(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if strings.EqualFold(u.Username, username) {
			return u.Role == roleAdmin && u.TOTPEnabled && u.TOTPSecret != ""
		}
	}
	return false
}

func (s *userStore) totpSecret(username string) (secret string, hashes []string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if strings.EqualFold(u.Username, username) {
			if !(u.Role == roleAdmin && u.TOTPEnabled && u.TOTPSecret != "") {
				return "", nil, false
			}
			h := append([]string(nil), u.TOTPRecoveryHash...)
			return u.TOTPSecret, h, true
		}
	}
	return "", nil, false
}

func (s *userStore) enableTOTP(username, secret string, recoveryHashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if !strings.EqualFold(s.Users[i].Username, username) {
			continue
		}
		if s.Users[i].Role != roleAdmin {
			return errors.New("TOTP is only available for admin accounts")
		}
		s.Users[i].TOTPSecret = secret
		s.Users[i].TOTPEnabled = true
		s.Users[i].TOTPRecoveryHash = append([]string(nil), recoveryHashes...)
		return s.save()
	}
	return fmt.Errorf("user %q not found", username)
}

func (s *userStore) disableTOTP(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if !strings.EqualFold(s.Users[i].Username, username) {
			continue
		}
		s.Users[i].TOTPSecret = ""
		s.Users[i].TOTPEnabled = false
		s.Users[i].TOTPRecoveryHash = nil
		return s.save()
	}
	return fmt.Errorf("user %q not found", username)
}

// consumeRecoveryCode removes a matching recovery hash after a successful use.
func (s *userStore) consumeRecoveryCode(username, code string) bool {
	sum := hashRecoveryCode(code)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if !strings.EqualFold(s.Users[i].Username, username) {
			continue
		}
		for j, h := range s.Users[i].TOTPRecoveryHash {
			if subtle.ConstantTimeCompare([]byte(h), []byte(sum)) == 1 {
				s.Users[i].TOTPRecoveryHash = append(s.Users[i].TOTPRecoveryHash[:j], s.Users[i].TOTPRecoveryHash[j+1:]...)
				_ = s.save()
				return true
			}
		}
		return false
	}
	return false
}

var errInvalidCredentials = errors.New("invalid username or password")

// Argon2id parameters (OWASP-oriented; t raised for offline-crack resistance).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash returns a real Argon2id hash used only to equalize login timing.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		h, err := hashPassword("dingbap-dummy-password-not-a-real-account")
		if err != nil {
			// Fallback encoding so verifyPassword still does work if RNG fails at init.
			dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return
		}
		dummyHash = h
	})
	return dummyHash
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
