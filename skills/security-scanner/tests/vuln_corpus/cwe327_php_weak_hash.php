<?php
// CWE-327: md5 для хеширования пароля (быстрый хеш без соли)
$password = $_POST['password'];
$hash = md5($password);
echo "stored";
