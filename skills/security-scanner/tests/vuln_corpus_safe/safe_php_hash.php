<?php
// Безопасно: password_hash (bcrypt) вместо md5/sha1
$password = $_POST['password'];
$hash = password_hash($password, PASSWORD_DEFAULT);
echo "stored";
