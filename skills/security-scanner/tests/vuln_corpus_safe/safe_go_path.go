package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const baseDir = "/var/www/files"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	clean := filepath.Clean(r.URL.Query().Get("file"))
	full := filepath.Join(baseDir, clean)
	// проверка префикса: результат обязан остаться внутри базового каталога
	if !strings.HasPrefix(full, baseDir+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
