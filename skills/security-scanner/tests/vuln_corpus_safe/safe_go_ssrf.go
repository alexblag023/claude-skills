package main

import (
	"io"
	"net/http"
)

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	env := r.URL.Query().Get("env")
	// allow-list: исходящий URL выбирается из констант, данные запроса в него не попадают
	var url string
	switch env {
	case "prod":
		url = "https://api.internal.example/health"
	case "staging":
		url = "https://staging.internal.example/health"
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "fetch error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
