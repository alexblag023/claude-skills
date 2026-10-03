<?php
// CWE-22 / LFI: путь к файлу берётся из $_GET без нормализации
$page = $_GET['page'];
include "/var/www/pages/" . $page;
