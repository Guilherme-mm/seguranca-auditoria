<?php
    

    $servername = "172.30.53.58";
    $username = "root";
    $password = "@Dlink05";

    // Create connection
    $conn = new mysqli($servername, $username, $password, "db", 3306);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    } 

    echo "Connected successfully";

?>
