<?php
// CWE-79: вывод $_GET в HTML без htmlspecialchars
$name = $_GET['name'];
echo "<h1>Hello, " . $name . "</h1>";
