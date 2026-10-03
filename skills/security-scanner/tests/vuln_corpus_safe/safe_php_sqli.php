<?php
// Безопасно: подготовленное выражение PDO с параметром
$pdo = new PDO("mysql:host=localhost;dbname=shop", "app", getenv("DB_PASS"));
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$row = $stmt->fetch();
