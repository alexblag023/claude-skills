package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const baseDir = "/var/www/files"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(filepath.Join(baseDir, r.URL.Query().Get("file")))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
