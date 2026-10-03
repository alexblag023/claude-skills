package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

func sqliHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
