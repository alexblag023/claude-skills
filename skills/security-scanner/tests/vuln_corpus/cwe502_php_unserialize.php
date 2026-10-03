<?php
// CWE-502: небезопасная десериализация данных из cookie
$prefs = unserialize($_COOKIE['prefs']);
echo "ok";
