<?php
    

    $servername = "127.0.0.1";
    $username = "root";
    $password = "cefet123";

    // Create connection
    $conn = new mysqli($servername, $username, $password, "db", 3306);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 

    echo "Connected successfully";

?>