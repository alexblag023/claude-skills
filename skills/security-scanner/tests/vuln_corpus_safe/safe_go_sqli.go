package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func sqliHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// параметризованный запрос: ввод идёт отдельным аргументом ($1), не в текст SQL
	rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
