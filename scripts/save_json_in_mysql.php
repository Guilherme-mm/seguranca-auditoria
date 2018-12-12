<?php 
    require_once ('import_json_to_mysql.php');

    $conecao = $conn;

    $dataOutput = file_get_contents('.\..\datasets\dataOutput.json');
    $dataHost = json_decode($dataOutput,true);
    $dominio = '';
    $hostsAgrupados = array();
    foreach ($dataHost as $key => $hostAvaliado) {
        if( array_key_exists('url',$hostAvaliado)){

            $dominio = parse_url($hostAvaliado['url'])['host'];
            
            if( ! array_key_exists($dominio,$hostsAgrupados)){
                $hostsAgrupados[$dominio] = criarHost($hostAvaliado);
                $hostsAgrupados[$dominio]['domain'] = $dominio;
            }else{
                $noticia = criarNoticia($hostAvaliado);
                $hostsAgrupados[$dominio]['urls'][] = $noticia;
            }

        }
    }
    foreach ($hostsAgrupados as $key => $host) {
        persistirHost($conecao,$host);
        // break;
    }
    // echo "<pre>";
    // var_dump( $hostsAgrupados);

    function criarHost($host){
        $novoHost = array();
        
        if(isset($host['ip'])){
            $novoHost['ip'] = $host['ip'];
        }
        if(isset($host['hostData']['location']['isEU'])){
            $novoHost['is_eu'] = $host['hostData']['location']['isEU'];
        }
        if(isset($host['hostData']['location']['continent'])){
            $novoHost['continent'] = $host['hostData']['location']['continent'];
        }
        if(isset($host['hostData']['location']['country'])){
            $novoHost['country'] = $host['hostData']['location']['country'];
        }
        if(isset($host['hostData']['location']['region'])){
            $novoHost['region'] = $host['hostData']['location']['region'];
        }
        if(isset($host['hostData']['location']['city'])){
            $novoHost['city'] = $host['hostData']['location']['city'];
        }
        if(isset($host['hostData']['location'])){
            $novoHost['location'] = $host['hostData']['location'];
        }
        if(isset($host['hostData']['asn'])){
            $novoHost['asn'] = $host['hostData']['asn'];
        }
        if(isset($host['hostData']['organisation'])){
            $novoHost['organisation'] = $host['hostData']['organisation'];
        }
        if(isset($host['hostData']['threatData']['is_tor'])){
            $novoHost['is_tor'] = $host['hostData']['threatData']['is_tor'];
        }
        if(isset($host['hostData']['threatData']['is_proxy'])){
            $novoHost['is_proxy'] = $host['hostData']['threatData']['is_proxy'];
        }
        if(isset($host['hostData']['threatData']['is_anonymous'])){
            $novoHost['is_anonymous'] = $host['hostData']['threatData']['is_anonymous'];
        }
        if(isset($host['hostData']['threatData']['is_known_attacker'])){
            $novoHost['is_known_attacker'] = $host['hostData']['threatData']['is_known_attacker'];
        }
        if(isset($host['hostData']['threatData']['is_known_abuser'])){
            $novoHost['is_known_abuser'] = $host['hostData']['threatData']['is_known_abuser'];
        }
        if(isset($host['hostData']['threatData']['is_threat'])){
            $novoHost['is_threat'] = $host['hostData']['threatData']['is_threat'];
        }
        if(isset($host['hostData']['threatData']['is_bogon'])){
            $novoHost['is_bogon'] = $host['hostData']['threatData']['is_bogon'];
        }
        $novoHost['urls'] =  array();

        $noticia = criarNoticia($host);
        $novoHost['urls'][] = $noticia;

        return $novoHost;
    }
    function criarNoticia($host){
        $noticia = array();
        if(isset($host['url'])){
            $noticia['url'] = $host['url'];
        }
        if(isset($host['httpVersion'])){
            $noticia['http_version'] = $host['httpVersion'];
        }
        if(isset($host['httpCode'])){
            $noticia['http_code'] = $host['httpCode'];
        }
        if(isset($host['alarmWords'])){
            $noticia['alarm_words_count'] = $host['alarmWords'];
        }
        if(isset($host['Server'])){
            $noticia['server_type'] = $host['Server'];
        }
        if(isset($host['url'])){
            $noticia['host_id'] = $host['url'];
        }
        return $noticia;
    }

    function persistirHost($conecao,$host){
        if ($conecao->connect_error) {
            die("Connection failed: " . $conecao->connect_error);
        } 

        $sql = "INSERT INTO host_tb ( ip, domain, is_eu, continent, country, region, city, asn, organisation, is_tor, is_proxy, is_anonymous, is_known_attacker, is_known_abuser, is_threat, is_bogon)
        VALUES ( 
            '{$host['ip']}',
            '{$host['domain']}',
            '{$host['continent']}',
            '{$host['country']}',
            '{$host['region']}',
            '{$host['city']}',
            '{$host['asn']}',
            '{$host['organisation']}',
            ". valorBooleano($host['is_eu']) .",
            ". valorBooleano($host['is_tor']) .",
            ". valorBooleano($host['is_proxy']) .",
            ". valorBooleano($host['is_anonymous']) .",
            ". valorBooleano($host['is_known_attacker']) .",
            ". valorBooleano($host['is_known_abuser']) .",
            ". valorBooleano($host['is_threat']) .",
            ". valorBooleano($host['is_bogon']) ."
        )";
        $idHost = 0;
        
        if ($conecao->query($sql) === TRUE) {
            $idHost = $conecao->insert_id;
            echo "New record created successfully. Last inserted ID is: " . $idHost;
            foreach ($host['urls'] as $key => $value) {
                persistirLinks($conecao,$idHost,$value);
            }
                        
        } else {
            echo "Error: " . $sql . "<br>" . $conecao->error;
        }
    }
    function persistirLinks($conecao,$idHost,$links){
        if ($conecao->connect_error) {
            die("Connection failed: " . $conecao->connect_error);
        } 
        $alarmWordsCount = '0';
        if(isset($links['alarm_words_count'])){
            $alarmWordsCount = $links['alarm_words_count'];
        }

        $sql = "INSERT INTO url_tb ( url, http_code, server_type, host_id , alarm_words_count)
        VALUES (
            '{$links['url']}', 
            '{$links['http_code']}', 
            '{$links['server_type']}', 
            {$idHost}, 
            {$alarmWordsCount}
            )";
        echo $sql;
        if ($conecao->query($sql) === TRUE) {
            $last_id = $conecao->insert_id;
            echo "New record created successfully. Last inserted ID is: " . $last_id;
           
        } else {
            echo "Error: " . $sql . "<br>" . $conecao->error;
        }
    }
    
    function valorBooleano( $val ){
        if(!is_null($val)){
            return 'false';
        }
        return ($val === true);
    }
?>