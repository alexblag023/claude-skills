<?php
// CWE-89: конкатенация $_GET в SQL-запрос
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$row = mysqli_fetch_assoc($result);
