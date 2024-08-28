# Implementation of "Efficient Secure Aggregation for Privacy-Preserving Federated Machine Learning"

## Code Structure

- **ServerCode/**: Contains the `Server.py` file, which handles the server-side logic in the system.
- **UserCode/**: Contains the `User.py` file, which manages the operations of users participating in the system.
- **AssistingNodeCode/**: Contains the `AssistingNodeCode.py` file, which manages the operations of assisting nodes in the system.

## How to Run

To run the system, use the following command:

```bash
./script.sh <number_of_users> <number_of_assisting_nodes> <without_or_with_commitment>
```

### Parameters:

- `<number_of_users>`: The number of users participating in the federated learning process. Must be greater than 2.
- `<number_of_assisting_nodes>`: The number of assisting nodes in the system.
- `<without_or_with_commitment>`: Set to `0` to run without commitment (i.e., without model integrity check) or `1` to run with commitment (i.e., with model integrity check).

### Examples:

**Running with 400 users, 3 assisting nodes, and without commitment:**

```bash
./script.sh 400 3 0
```

**Running with 200 users, 3 assisting nodes, and with commitment:**

```bash
./script.sh 200 3 1
```
