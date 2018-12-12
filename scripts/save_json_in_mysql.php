;<?php 
    require_once ('import_json_to_mysql.php');

    $conecao = $conn;
    $hosts = array();

    $dataOutput = file_get_contents('.\..\datasets\dataOutput.json');
    $dataHost = json_decode($dataOutput,true);
    $hostName = '';
    foreach ($dataHost as $key => $hostAvaliado) {
        if( array_key_exists('url',$hostAvaliado)){

            $hostName = parse_url($hostAvaliado['url']);

            echo( $hostName['host'] . $hostName['path'] . '<br>' );
        }
    }
?>