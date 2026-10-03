package main

import (
	"io"
	"net/http"
)

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, "fetch error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
