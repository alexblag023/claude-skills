package main

import (
	"net/http"
	"os"
)

func adminHandler(w http.ResponseWriter, r *http.Request) {
	// секрет читается из окружения, не хранится в коде
	apiPassword := os.Getenv("API_TOKEN")
	if apiPassword != "" && r.Header.Get("X-Token") == apiPassword {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
