package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	// SHA-256 вместо MD5/SHA-1 (для хранения паролей предпочтительнее bcrypt/argon2)
	sum := sha256.Sum256([]byte(password))
	digest := hex.EncodeToString(sum[:])
	w.Write([]byte(digest))
}
