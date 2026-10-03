<?php
// CWE-78: ввод пользователя передаётся в shell_exec без экранирования
$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host);
echo "done";
