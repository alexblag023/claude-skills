package main

import (
	"net/http"
	"os/exec"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c1 "+host).Output()
	if err != nil {
		http.Error(w, "exec error", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
