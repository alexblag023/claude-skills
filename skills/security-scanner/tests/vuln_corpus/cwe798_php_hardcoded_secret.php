<?php
// CWE-798: пароль БД зашит строковым литералом в коде
$db_password = "S3cr3tP@ss2024";
$conn = mysqli_connect("localhost", "root", $db_password, "app");
