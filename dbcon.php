<?php 
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "login";
// Create connection
$connect2db= mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$connect2db) {
    die("Connection failed: " . mysqli_connect_error());
}
?>