<?php

include "utils.php";

const GET_AUDIT_FROM_API = false;

//Caso seja necessário, coleta os dados de auditoria e joga num json
if(GET_AUDIT_FROM_API){
    echo "#### Getting audit data from external API ####" . PHP_EOL;
    $falseUrls = getFalseUrls();
    
    $falseUrlData = [];
    $ipdataAccessKey = file_get_contents("ipdataAccessKey.txt"); //Outra opção é usar o ipinfo.io
    echo "# Getted API access key: $ipdataAccessKey" . PHP_EOL;
    foreach($falseUrls as $url){
        //Getting the host IP
        $hostIp = gethostbyname(parse_url($url, PHP_URL_HOST));
        
        echo "# Getting data for $hostIp" . PHP_EOL;
        
        //cURL handler configuration
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://api.ipdata.co/$hostIp?api-key=$ipdataAccessKey");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            "Accept: application/json"
        ));
        
        //Running the query
        $response = json_decode(curl_exec($ch));
        curl_close($ch);
        
        //Data Mapping 
        $desiredData = (object)[
            "ip" => $response->ip,
            "isEU" => $response->is_eu,
            "continent" => $response->continent_name,
            "country" => $response->country_name,
            "city" => $response->city,
            "region" => $response->region,
            "lat" => $response->latitude,
            "long" => $response->longitude,
            "asn" => $response->asn,
            "organisation" => $response->organisation,
            "threatData" => $response->threat
        ];
    
        $falseUrlData[] = $desiredData;
    }
    
    //Creates a JSON file to save the results (for now);
    file_put_contents("../datasets/ipdataoutput.json", json_encode($falseUrlData));
} else {
    
}

