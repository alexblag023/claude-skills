package main

import (
	"net/http"
	"os/exec"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// фиксированная программа + argv: без оболочки, ввод не интерпретируется
	out, err := exec.Command("ping", "-c1", "--", host).Output()
	if err != nil {
		http.Error(w, "exec error", http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
