<?php
// Безопасно: секрет берётся из переменной окружения, не из литерала
$db_password = getenv("DB_PASS");
$conn = mysqli_connect("localhost", "root", $db_password, "app");
