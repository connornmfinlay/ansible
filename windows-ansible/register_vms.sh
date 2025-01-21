#!/bin/bash

# Varialbes Passed By Rundeck
declare -gr OS_PROJECT=$1
declare -gr WIN_PROJECT=$2
declare -gr API_TOKEN=$3

declare -gr RD_JOB_ID=$(< /deployments/$OS_PROJECT-$WIN_PROJECT/JOB_ID)
declare -gr RD_EXEC_ID=$(< /deployments/$OS_PROJECT-$WIN_PROJECT/EXEC_ID)

export OS_CLIENT_CONFIG_FILE=/deployments/$OS_PROJECT-$WIN_PROJECT/clouds.yaml

# check directory exists
if [[ ! -d /deployments/$OS_PROJECT-$WIN_PROJECT/ ]]; then
    >&2 echo "Directory Doesn't exist"
    exit 1
fi

initialize_json() {
    declare -r OUTPUT_FILE="/deployments/$OS_PROJECT-$WIN_PROJECT/data.json"

    jq -n '
    {
        "job_id": "'$RD_JOB_ID'",
        "execution_id": "'$RD_EXEC_ID'",
        "status": "ok",
        "data": {
            "DC": {},
            "WB": {"load_balancer": true, VM: []},
            "APP": {"load_balancer": false, VM: []},
            "GPU": {"load_balancer": false, VM: []}
        }
    }' > $OUTPUT_FILE
    declare -g -r VM_JSON="/deployments/$OS_PROJECT-$WIN_PROJECT/data.json"
}

add_vm() {

    declare -r NAME=$1
    declare -r UUID=$2
    declare -r IP=$3
    declare -r TYPE=$4

    if [[ $TYPE == "DC" ]]; then
        jq ".data.${TYPE} += {\"name\": \"${NAME}\", \"ip\": \"${IP}\", \"uuid\": \"${UUID}\"}" $VM_JSON > temp.json
        mv -f temp.json $VM_JSON
    else
        jq ".data.${TYPE}.VM += [{\"name\": \"${NAME}\", \"ip\": \"${IP}\", \"uuid\": \"${UUID}\"}]" $VM_JSON > temp.json
        mv -f temp.json $VM_JSON
    fi
}

post_request() {
    declare -r API_ENDPOINT='https://portal.eidf.ac.uk/job/api/notification'
    jq -c . $VM_JSON
    curl \
    -X POST \
    -H "content-type: application/json" \
    -H "accept: application/json" \
    -H "Authorization: Token $API_TOKEN" \
    -d "'$(jq -c . $VM_JSON)'" \
    $API_ENDPOINT
}

main() {
    initialize_json
    while read -r VM; do
        declare vm_uuid=$(jq -r '.ID' <<< "$VM")
        declare vm_name=$(jq -r '.Name' <<< "$VM")
        declare vm_ip=$(jq -r '.IP' <<< "$VM")

        if [[ "$vm_name" =~ ^$OS_PROJECT-$WIN_PROJECT-dc01$ ]]; then
            add_vm $vm_name $vm_uuid $vm_ip 'DC'

        elif [[ "$vm_name" =~ ^$OS_PROJECT-$WIN_PROJECT-wb[0-9]+$ ]]; then
            add_vm $vm_name $vm_uuid $vm_ip 'WB'

        elif [[ "$vm_name" =~ ^$OS_PROJECT-$WIN_PROJECT-app[0-9]+$ ]]; then
            add_vm $vm_name $vm_uuid $vm_ip 'APP'

        elif [[ "$vm_name" =~ ^$OS_PROJECT-$WIN_PROJECT-gpu[0-9]+$ ]]; then
            add_vm $vm_name $vm_uuid $vm_ip 'GPU'
        fi
    done < <(openstack --os-cloud $OS_PROJECT server list -f json | jq -c '.[] | {ID, Name, IP: .Networks.external[0]}')

    post_request
}

main
