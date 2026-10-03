<?php
// Безопасно: json_decode вместо unserialize для недоверенных данных
$prefs = json_decode($_COOKIE['prefs'], true);
echo "ok";
