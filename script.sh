#!/bin/bash

# Set the project directory based on the current working directory
PROJECT_DIR=$(pwd)

# Determine OS and set flags for OpenSSL path accordingly
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OPENSSL_LIB_PATH=""
    OPENSSL_INCLUDE_PATH=""
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS, adjust as needed if paths differ
    OPENSSL_LIB_PATH="-L$(brew --prefix openssl@3)/lib"
    OPENSSL_INCLUDE_PATH="-I$(brew --prefix openssl@3)/include"
else
    echo "Unsupported operating system."
    exit 1
fi

g++ -shared -o $PROJECT_DIR/aggregation.so -fPIC $PROJECT_DIR/aggregation.cpp
g++ -o $PROJECT_DIR/AesModeCTR $PROJECT_DIR/AesModeCTR-master/AesModeCTR.cpp $PROJECT_DIR/AesModeCTR-master/TestAesModeCTR.cpp $OPENSSL_INCLUDE_PATH $OPENSSL_LIB_PATH -lssl -lcrypto

# Default values for options
num_users="" # Number of users
num_assisting_nodes="" # Number of assisting nodes
commitment="" # Commitment mode: 0 or 1
printAggOutput=0 # Output behavior: 0, 1, or 2 (default 0)
server_port=9000 # Server port number (default 9000)
bandwidth_mode=0 # Bandwidth mode: 0 or 1 (default 0)

# Function to display usage information
usage() {
    echo -e "\nUsage: $0 -u <number_of_users> -a <number_of_assisting_nodes> -c <commitment> [-o <printAggOutput>] [-p <server_port>]"
    echo -e "\nOptions:"
    echo "  -u <number_of_users>             Required. Number of users (must be greater than 2)"
    echo "  -a <number_of_assisting_nodes>   Required. Number of assisting nodes"
    echo "  -c <commitment>                  Required. 0: without commitment, 1: with commitment"
    echo "  -o <printAggOutput>              Optional. 0: no print, 1: print result, 2: print summary (default: 0)"
    echo "  -p <server_port>                 Optional. Server port (default: 9000, range: 2000-60000)"
    echo -e "\nExample:"
    echo "  $0 -u 200 -a 3 -c 0"
    echo "  $0 -u 200 -a 3 -c 1 -o 2 -p 10000"
    echo -e "\n"
    exit 1
}

usage() {
    echo -e "\nUsage: $0 -u <number_of_users> -a <number_of_assisting_nodes> -c <commitment> [-o <printAggOutput>] [-p <server_port>] [-b <bandwidth_mode>]"
    echo -e "\nOptions:"
    echo "  -u <number_of_users>              Required. Number of users (must be greater than 2)"
    echo "  -a <number_of_assisting_nodes>    Required. Number of assisting nodes"
    echo "  -c <commitment>                   Required. 0: without commitment, 1: with commitment"
    echo "  -o <printAggOutput>               Optional. 0: no print, 1: print result, 2: print summary (default: 0)"
    echo "  -p <server_port>                  Optional. Server port (default: 9000, range: 2000-60000)"
    echo "  -b <bandwidth_mode>               Optional. 0: no print, 1: print outbound bandwidth, 2: only print outbound bandwidth (default: 0)"
    echo -e "\nExample:"
    echo "  $0 -u 200 -a 3 -c 0 -b 1"
    echo "  $0 -u 200 -a 3 -c 1 -o 2 -p 10000"
    echo "  $0 -u 200 -a 3 -p 10000 -b 2"
    echo -e "\n"
    exit 1
}

# Parse command-line arguments
while getopts "u:a:c:o:p:b:" opt; do
    case ${opt} in
        u) num_users=$OPTARG ;;
        a) num_assisting_nodes=$OPTARG ;;
        c) commitment=$OPTARG ;;
        o) printAggOutput=$OPTARG ;;
        p) server_port=$OPTARG ;;
        b) bandwidth_mode=$OPTARG ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$num_users" ] || [ -z "$num_assisting_nodes" ] || [ -z "$commitment" ]; then
    echo -e "\nError: Missing required arguments!"
    usage
fi

# Validate number of users
if [ "$num_users" -le 2 ]; then
    echo -e "\nError: number_of_users must be greater than 2."
    usage
fi

# Validate commitment value
if [ "$commitment" -ne 0 ] && [ "$commitment" -ne 1 ]; then
    echo -e "\nError: commitment must be 0 (without commitment) or 1 (with commitment)."
    usage
fi

# Validate printAggOutput value
if [ "$printAggOutput" -ne 0 ] && [ "$printAggOutput" -ne 1 ] && [ "$printAggOutput" -ne 2 ]; then
    echo -e "\nError: printAggOutput must be 0 (no print), 1 (print result), or 2 (print summary)."
    usage
fi

# Validate server_port value
if [ "$server_port" -lt 2000 ] || [ "$server_port" -gt 60000 ]; then
    echo -e "\nError: server_port must be between 2000 and 60000."
    exit 1
fi

# Validate bandwidth_mode value
if [ "$bandwidth_mode" -ne 0 ] && [ "$bandwidth_mode" -ne 1 ] && [ "$bandwidth_mode" -ne 2 ]; then
    echo -e "\nError: bandwidth_mode must be 0 (no print), 1 (print outbound bandwidth), or 2 (only print outbound bandwidth)."
    usage
fi

# Update the port.txt file
{
    echo "ServerPort = $server_port"
    echo "FirstAssistantNodePort = $((server_port + 2000))"
} > port.txt

# Start the server
python3 $PROJECT_DIR/ServerCode/Server.py $num_users $num_assisting_nodes $commitment $printAggOutput $bandwidth_mode &

# Allow server to initialize
sleep 1

# Start assisting nodes
for ((i=1; i<=$num_assisting_nodes; i++)); do
    python3 $PROJECT_DIR/AssistingNodeCode/AssistingNodeCode.py $i $num_users $num_assisting_nodes $commitment $bandwidth_mode &
    sleep 0.01
done

# Start user processes
for ((i=1; i<=$num_users; i++)); do
    python3 $PROJECT_DIR/UserCode/User.py $i $num_users $num_assisting_nodes $commitment $bandwidth_mode &
    
    if [ $i -eq $num_users ]; then
        if [ $commitment -eq 1 ]; then
            sleep 10
        else
            sleep 1
        fi
    else
        if [ $commitment -eq 1 ]; then
            sleep 0.01
        fi
    fi
done

wait
