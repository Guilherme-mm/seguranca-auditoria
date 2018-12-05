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
?>