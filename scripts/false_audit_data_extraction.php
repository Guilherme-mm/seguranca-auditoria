<?php

include "utils.php";
require "../vendor/autoload.php";

use Nmap\Nmap;

const GET_AUDIT_FROM_API = false;
const GET_HOST_SYSTEM_DATA_FROM_API = false;
const GET_SERVER_LANGUAGE = false;
const GET_ALARM_WORDS_COUNT = false;

$falseUrlData = [];

//Coleta os dados de auditoria da API externa ou do JSON previamente preenchido
if(GET_AUDIT_FROM_API){
    echo "#### Getting audit data from external API ####" . PHP_EOL;
    $falseUrls = getFalseUrls();
    
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
            "url" => $url,
            "hostData" => (object)[
                "location" => (object) [
                    "isEU" => $response->is_eu,
                    "continent" => $response->continent_name,
                    "country" => $response->country_name,
                    "city" => $response->city,
                    "region" => $response->region,
                    "lat" => $response->latitude,
                    "long" => $response->longitude,
                ],
                "asn" => $response->asn,
                "organisation" => $response->organisation,
                "threatData" => $response->threat
            ],
        ];
    
        $falseUrlData[] = $desiredData;
    }
    
    //Creates a JSON file to save the results (for now);
    persistDataOnFile($falseUrlData, "dataOutput.json");
} else {
    echo "#### Getting audit data cached JSON file ####" . PHP_EOL;
    $falseUrlData = json_decode(file_get_contents("../datasets/dataOutput.json"));
}

//Coleta dados sobre o system dos hosts e atualiza o JSON de output gerado na etapa anterior
if(GET_HOST_SYSTEM_DATA_FROM_API){
    echo "#### Getting hosts system information from external API ####" . PHP_EOL;

    $nmap = new Nmap();
    $nmap
        ->enableOsDetection(true)
        ->enableServiceInfo(true);

    foreach ($falseUrlData as &$data) {
        try{
            $url = $data->url;
            $hostIp = $data->ip;

            echo "# Getting data from $url" . PHP_EOL;
            
            $tempOutputFilePath = $nmap->scan(["$url"]);
            $outputXMLString = file_get_contents($tempOutputFilePath);
            $outputXML = simplexml_load_string($outputXMLString);
            $outputAsJSON = json_encode($outputXML);
            $outputAsObject = json_decode($outputAsJSON);

            $clearedResult = clearNmapResult($outputAsObject);
            
            $data->hostData->hostNames = $clearedResult->host->hostNames;
            $data->hostData->ports = $clearedResult->host->ports;
            $data->OSData = $clearedResult->OS;
        } catch(\Exception $e){
            continue;
        }
        
        // var_dump($outputAsObject);
        // exit;
    }

    persistDataOnFile($falseUrlData, "dataOutput.json");
}

//Coleta dados de cabeçalho para determinar a linguagem da pagina
if(GET_SERVER_LANGUAGE){
    echo "#### Getting Language information from external URLs ####" . PHP_EOL;
    foreach($falseUrlData as &$urlData){
        echo "# Getting data from $urlData->url" . PHP_EOL;
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $urlData->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, 1);
            
        //Running the query
        $response = curl_exec($ch);
        $info = curl_getinfo($ch);
        $headers = get_headers_from_curl_response($response);
        curl_close($ch);
    
        if(isset($headers["Server"])){
            $urlData->Server = $headers["Server"];
        }
    
        if(isset($headers["http_code"])){
            $urlData->httpCode = $headers["http_code"];
        }
    
        if(isset($headers["X-Powered-By"])){
            $urlData->serverLanguage = $headers["X-Powered-By"];
        }
    
    }
    
    persistDataOnFile($falseUrlData, "dataOutput.json");
}

//Coleta dados relacionados ao HTML
if(GET_ALARM_WORDS_COUNT){
    echo "#### Getting alarmist words count from pages content ####" . PHP_EOL;
    $alarmWordsList = ["Atenção", "Atencao", "Ameaçar", "Perigo", "Repassem", "Espalhem", "Urgente", "Enganado", "Farsa", "Enganação", "Enganacao", "Enganar", "Sacanagem", "Colabore", "Divulgação", "Divulgacao", "Divulgue", "Compartilhe", "Contatos", "Corja", "Vergonha", "Grave", "Gravíssimo"];
    
    foreach($falseUrlData as &$urlData){
        echo "# Counting for $urlData->url" . PHP_EOL;
        $ch = curl_init();
    
        curl_setopt($ch, CURLOPT_URL, $urlData->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, 1);
    
        $response = curl_exec($ch);
        $headers = get_headers_from_curl_response($response);
        $alarmWordsCount = 0;
    
        if(strpos($headers["http_code"], "404")){
            continue;
        } else {
            $pageContent = strip_tags($response);
            $pageContent = mb_strtolower($pageContent);
    
            foreach($alarmWordsList as $word){
                $alarmWordsCount += substr_count($pageContent, mb_strtolower($word));
            }
    
            $urlData->alarmWords = $alarmWordsCount;
        }
    }
    
    persistDataOnFile($falseUrlData, "dataOutput.json");
}


