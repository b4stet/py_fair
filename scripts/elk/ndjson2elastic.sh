#!/bin/bash 

operation=$1

post_elastic(){
    data=$1
    curl -s -X POST "127.0.0.1:9200/_bulk?timeout=5m" -H "Content-Type: application/json" --data-binary @<(cat $data) -o result.json
    echo -n 'Chunk errors (null = success):'
    cat result.json | jq '.items[].index.error.reason' | sort | uniq -c |sort -rn
}
export -f post_elastic

case $operation in
    'create')
        index_name=$2
        index_config=$3
        curl -X PUT "127.0.0.1:9200/${index_name}" -H 'Content-Type: application/json' -d @${index_config}
        ;;

    'read')
        curl "127.0.0.1:9200/_cat/indices?v"
        ;;

    'update')
        index=$2
        data=$3

        ES_INDEX=${index} jq -c '. | {"index": {"_index":env.ES_INDEX}}, .' ${data} | split -l 20000 --numeric-suffixes --filter="post_elastic $FILE" - "es_data."  
        ;;

    'delete')
        index=$2
        curl -X DELETE "127.0.0.1:9200/${index}"
        ;;
esac