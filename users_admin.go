package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func handleUsersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"users": users.listPublic(),
	})
}

func handleUsersCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if body.Role == "" {
		body.Role = roleViewer
	}
	if err := users.addUser(body.Username, body.Password, body.Role); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, "User created")
}

func handleUsersDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if s := sessionFromCtx(r); s != nil && strings.EqualFold(s.Username, body.Username) {
		jsonErr(w, http.StatusBadRequest, "Cannot delete your own account while logged in")
		return
	}
	if err := users.deleteUser(body.Username); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sessions != nil {
		sessions.destroyByUsername(body.Username)
	}
	jsonOK(w, "User deleted")
}

func handleUsersSetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if err := users.setPassword(body.Username, body.Password); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sessions != nil {
		sessions.destroyByUsername(body.Username)
	}
	jsonOK(w, "Password updated — user must sign in again")
}

func handleUsersSetRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if s := sessionFromCtx(r); s != nil && strings.EqualFold(s.Username, body.Username) && body.Role != roleAdmin {
		jsonErr(w, http.StatusBadRequest, "Cannot demote your own account")
		return
	}
	if err := users.setRole(body.Username, body.Role); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sessions != nil {
		sessions.destroyByUsername(body.Username)
	}
	jsonOK(w, "Role updated")
}

// handleChangeOwnPassword lets any logged-in user change their password.
func handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s := sessionFromCtx(r)
	if s == nil {
		jsonErr(w, http.StatusUnauthorized, "Not logged in")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if _, err := users.authenticate(s.Username, body.CurrentPassword); err != nil {
		jsonErr(w, http.StatusBadRequest, "Current password is incorrect")
		return
	}
	if err := users.setPassword(s.Username, body.NewPassword); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if sessions != nil {
		sessions.destroyByUsername(s.Username)
		sessions.clearCookie(w)
	}
	jsonOK(w, "Password updated — please sign in again")
}
