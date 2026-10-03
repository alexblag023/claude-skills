<?php
// Безопасно: basename + проверка по allow-list
$page = basename($_GET['page']);
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed, true)) {
    include "/var/www/pages/" . $page . ".php";
}
