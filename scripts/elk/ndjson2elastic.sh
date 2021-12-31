#!/bin/bash 

operation=$1

case $operation in
    'create')
        index_name=$2
        index_config=$3
        pipeline_name=$4
        pipeline_config=$5
        curl -X PUT "127.0.0.1:9200/_ingest/pipeline/${pipeline_name}" -H 'Content-Type: application/json' -d @${pipeline_config}
        curl -X PUT "127.0.0.1:9200/${index_name}" -H 'Content-Type: application/json' -d @${index_config}
        ;;

    'read')
        index=$2
        curl "127.0.0.1:9200/${index}"
        ;;

    'update')
        index=$2
        data=$3
        echo "Preparing data"
        split_prefix="es_data."
        jq -c '. | {"index": {}}, .' ${data} | split -l 20000 --numeric-suffixes - "${split_prefix}" 
        for filename in ./${split_prefix}*;
        do 
            echo "Ingesting ${filename}"
            curl -s -X POST "127.0.0.1:9200/${index}/_bulk" -H 'Content-Type: application/json' --data-binary @${filename} 
            echo -e "\n"
        done
        rm ${split_prefix}*
        ;;

    'delete')
        index=$2
        curl -X DELETE "127.0.0.1:9200/${index}"
        ;;
esac