<?php
// Безопасно: аргумент экранирован через escapeshellarg
$host = $_GET['host'];
$safe = escapeshellarg($host);
$output = shell_exec("ping -c 1 " . $safe);
echo "done";
