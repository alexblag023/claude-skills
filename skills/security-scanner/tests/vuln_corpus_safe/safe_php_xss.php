<?php
// Безопасно: вывод закодирован htmlspecialchars
$name = $_GET['name'];
echo "<h1>Hello, " . htmlspecialchars($name, ENT_QUOTES) . "</h1>";
