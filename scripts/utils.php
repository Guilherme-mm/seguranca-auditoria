<?php
    function getFalseUrls(){
        //Getting data from csv
        $csvFile = file('../datasets/false-urls.csv');
        $data = [];
        foreach ($csvFile as $line) {
            $data[] = str_getcsv($line);
        }
        
        $urlMap = [];
        $uniqueUrls = [];
        //cleaning identical urls
        foreach($data as $line){
            $url = $line[0];

            if(isset($urlMap[$url])){
                continue;
            } else {
                $urlMap[$url] = true;
                $uniqueUrls[] = $url;
            }

        }

        return $uniqueUrls;
    }

    function clearNmapResult($nmapResult){
        $clearedResult = (object)[
            "host" => (object)[],
            "OS" => (object)[]
        ];

        //Pegando dados do host
        //Se o nmap pegou dados de hostname:
        if(isset($nmapResult->host, $nmapResult->host->hostnames, $nmapResult->host->hostnames->hostname)){
            $clearedResult->host->hostNames = [];
            foreach($nmapResult->host->hostnames->hostname as $hostname){
                $clearedResult->host->hostNames[] = (object)[
                    "name" => $hostname->{"@attributes"}->name,
                    "type" => $hostname->{"@attributes"}->type
                ];
            }
        }

        //Se o nmap pegou dados de portas:
        if(isset($nmapResult->host, $nmapResult->host->ports, $nmapResult->host->ports->port)){
            $clearedResult->host->ports = [];

            foreach ($nmapResult->host->ports->port as $port) {
                $clearedPort = (object)[];
                if(isset($port->{"@attributes"})){
                    $clearedPort->protocol = $port->{"@attributes"}->protocol;
                    $clearedPort->id = $port->{"@attributes"}->portid;
                }
                if(isset($port->state)){
                    $clearedPort->state = $port->state->{"@attributes"}->state;
                    $clearedPort->stateReson = $port->state->{"@attributes"}->reason;
                }
                if(isset($port->service)){
                    $clearedPort->service = (object)[];
                    $clearedPort->service->name = $port->service->{"@attributes"}->name;
                    $clearedPort->service->product = $port->service->{"@attributes"}->product;
                    $clearedPort->service->version = $port->service->{"@attributes"}->version;
                    $clearedPort->service->extraInfo = $port->service->{"@attributes"}->extrainfo;
                    $clearedPort->service->OSType = $port->service->{"@attributes"}->ostype;
                    $clearedPort->service->method = $port->service->{"@attributes"}->method;
                    $clearedPort->service->conf = $port->service->{"@attributes"}->conf;
                }

                $clearedResult->host->ports[] = $clearedPort;
            }
        }

        //Se o nmap pegou resultados de OS pt1
        if(isset($nmapResult->host, $nmapResult->host->os)){
            if(isset($nmapResult->host->os->portused)){
                $clearedResult->OS->usedPorts = [];

                foreach($nmapResult->host->os->portused as $usedPort){
                    $clearedResult->OS->usedPorts[] = (object)[
                        "state" => $usedPort->{"@attributes"}->state,
                        "protocol" => $usedPort->{"@attributes"}->proto,
                        "id" => $usedPort->{"@attributes"}->id
                    ];
                }
            }

            if(isset($nmapResult->host->os->osmatch)){
                if(is_array($nmapResult->host->os->osmatch) && count($nmapResult->host->os->osmatch) > 0){
                    $mostProbableMatch = $nmapResult->host->os->osmatch[0];

                    $clearedResult->OS->OSGuess = (object)[];
                    $clearedResult->OS->OSGuess->name = $mostProbableMatch->{"@attributes"}->name;
                    $clearedResult->OS->OSGuess->accuracy = $mostProbableMatch->{"@attributes"}->accuracy;
                    $clearedResult->OS->OSGuess->class = [];
                    foreach($mostProbableMatch->osclass as $class){
                        $clearedResult->OS->OSGuess->class[] = (object)[
                            "type" => $class->{"@attributes"}->type,
                            "vendor" => $class->{"@attributes"}->vendor,
                            "family" => $class->{"@attributes"}->osfamily,
                            "generation" => $class->{"@attributes"}->osgen,
                            "accuracy" => $class->{"@attributes"}->accuracy,
                        ];
                    }
                }
            }
        }

        return $clearedResult;
    }

    function persistDataOnFile($data, $fileName){
        file_put_contents("../datasets/$fileName", json_encode($data));
    }
?>