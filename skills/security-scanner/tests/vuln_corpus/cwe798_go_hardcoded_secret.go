package main

import "net/http"

const apiPassword = "S3cr3t-Prod-Value!"

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Token") == apiPassword {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
