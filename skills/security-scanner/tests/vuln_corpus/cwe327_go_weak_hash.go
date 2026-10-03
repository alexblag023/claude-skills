package main

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	h := md5.New()
	h.Write([]byte(password))
	digest := hex.EncodeToString(h.Sum(nil))
	w.Write([]byte(digest))
}
