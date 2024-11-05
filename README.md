# Efficient Secure Aggregation for Privacy-Preserving Federated Machine Learning

This repository contains the full implementation of **e-SeaFL** paper (accepted to ACSAC 2024).

**Warning**: This code is a proof-of-concept prototype and is not ready for production use.

## Code Structure

- **ServerCode/**: Contains the `Server.py` file, which handles the server-side logic in the system.
- **UserCode/**: Contains the `User.py` file, which manages the operations of users participating in the system.
- **AssistingNodeCode/**: Contains the `AssistingNodeCode.py` file, which manages the operations of assisting nodes in the system.
- **AesModeCTR-master/**: Contains the C++ implementation for AES encryption in CTR mode.
- **Compilation Scripts**:
  - `auto_setup.sh`: Bash script to automatically install the required libraries and packages. 
  - `script.sh`: Bash script to compile necessary binaries (`aggregation.so`, `AesModeCTR`) and run the entire system.

## Prerequisites

Before running the system, ensure that the following software is installed:

- **Python 3.8+**
- **GCC** (for compiling C++ code)
- **OpenSSL** (for cryptographic operations)

## How to Run

To automatically install the required libraries and packages, run the following script:

```bash
./auto_setup.sh
```

### Running e-SeaFL Code

To run the e-SeaFL system, use the following command:

```bash
./script.sh -u <number_of_users> -a <number_of_assisting_nodes> -c <commitment> [-o <printAggOutput>] [-p <server_port>] [-b <bandwidth_mode>]
```

### Parameters:

- `-u <number_of_users>`: **Required**. The number of users participating in the federated learning process. Must be greater than 2.
- `-a <number_of_assisting_nodes>`: **Required**. The number of assisting nodes in the system.
- `-c <commitment>`: **Required**. Set to `0` to run without commitment (i.e., without model integrity check) or \`1\` to run with commitment (i.e., with model integrity check).
- `-o <printAggOutput>`: **Optional**. Controls the output behavior: 
  - `0`: No print (default).
  - `1`: Print result.
  - `2`: Print summary.
- `-b <bandwidth_mode>`: **Optional**. Controls the output behavior for outbound bandwidth: 
  - `0`: No print (default).
  - `1`: Print outbound bandwidth.
  - `2`: Only print outbound bandwidth.
- `-p <server_port>`: **Optional**. The port number for the server (default is \`9000\`, valid range is \`2000-60000\`).

#### Examples:

**Running a quick test with 25 users, 3 assisting nodes, without commitment, and printing the summary:**

```bash
./script.sh -u 25 -a 3 -c 0 -o 2 -p 10050
```

**Running a quick test with 20 users, 3 assisting nodes, with commitment, and printing the summary:**

```bash
./script.sh -u 20 -a 3 -c 1 -o 2 -p 10070
```

**Running with 400 users, 3 assisting nodes, and without commitment:**

```bash
./script.sh -u 400 -a 3 -c 0 -p 10400
```

**Running with 200 users, 3 assisting nodes, with commitment, and printing the summary:**

```bash
./script.sh -u 200 -a 3 -c 1 -o 2 -p 10300
```

**Running with 600 users, 3 assisting nodes, without commitment, and printing the outbound bandwidth:**

```bash
./script.sh -u 600 -a 3 -c 0 -b 1 -p 15000
```

## Artifact Documentation

For a detailed description of how to reproduce the results presented in the paper, please refer to our [Artifact Documentation](/Documents/ACSAC_2024_Artifact_Documentation_Efficient_Secure_Aggregation_for_Privacy-Preserving_Federated_Machine_Learning.pdf). 
  


