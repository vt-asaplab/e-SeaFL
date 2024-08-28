import socket
import struct
import time
import threading
import sys
import hashlib
import nacl.secret
import nacl.utils
import ecdsa
from ecdsa.ellipticcurve import CurveFp, Point
from ctypes import cdll, c_long, POINTER
import subprocess
import base64
from coincurve.keys import PrivateKey
import os

# Configuration
IP = "127.0.0.1" # Server IP address
FORMAT = "utf-8" # Encoding format
SIZE = 256000 # Buffer size for socket communication
WEIGHTLISTSIZE = 16000 # Size of the weight list for aggregation
CHUNKSIZE = 100 # Chunk for splitting data

# Load server port from configuration file
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
file_path = os.path.join(parent_dir, "port.txt")
PortFile = open(file_path, 'r')
Lines = PortFile.readlines()   
ServerPort = Lines[0].strip().split("=")[1].strip()

PORT = int(ServerPort)
ADDR = (IP, PORT) # Server address tuple (IP, Port)

# Global variables used throughout the code
clientAssistantSocket, s2 = socket.socketpair() # Sockets for internal communication between client and assistant node
assistantNodeSharedSecretDict = {} # Dictionary to map assistant node IDs to shared secrets
assistantNodePublicKeyDict = {} # Dictionary to map assistant node IDs to their public keys
AssistantNodeIDList = []
listOfAssistantNodeconnections = [] # List of connections to assistant nodes
messageM = [] # List to store masked info for the server
listOfEncryptedValue = [] # List to store encrypted rho 
rhoList = [] # List to store rho value used in commitments
Xvalue = [] # List to store x elliptic curve points
ADDRlist = [] # List to store addresses of assistant nodes
executionTime = [] # List to store execution times for shared secrets
decryptionTimeSetup = [] # List to store decryption times for setup phase
commitmentGenTime = [] # List to store commitment generation times

def printResults(User_ID, NumberOfUsers, timeMaliciousSetting, setupPhaseComputationTime1, aggTimeMaliciousSetting, aggTime, commitmentUse):
    if int(User_ID) == int(NumberOfUsers):
        """
        Print the setup and aggregation times.
        """
        print("\n==== Client RESULTS ====")
        SumExeTime = sum(executionTime)
        setupPhaseComputationTime1 += SumExeTime
        print("Client: Semi-Honest Setting (Setup Phase):",(setupPhaseComputationTime1) * 10**3, "ms")
        print("Client: Malicious Setting (Setup Phase):",(setupPhaseComputationTime1 + timeMaliciousSetting) * 10**3, "ms")
        print("Client: Semi-Honest Setting (Aggregation Phase):",(aggTime), "ms")
        aggTime += (aggTimeMaliciousSetting * 10**3)
        print("Client: Malicious Setting (Aggregation Phase):",(aggTime) , "ms")
        if commitmentUse == 1:
            print("Client: Decryption Time:",(sum(decryptionTimeSetup)) * 10**3 , "ms")
            print("Client: Commitment Time:",(commitmentGenTime[0] * 10**3) / 60000, "min")
        print("========================\n")

def validateAggregatedModel(finalWeightListAggregated, listOfGenerators):
    """
    Validate the aggregated model using the aggregated weight list and a list of generators.
    Algorithm 2 - Aggregation (Phase 2) - Step 6
    """    
    for i in range(len(finalWeightListAggregated)):
        rho_FinalWeight = rhoList[0] * finalWeightListAggregated[i]
        if i == 0:
            tempCompare = rho_FinalWeight * listOfGenerators[i]
        else:
            if i == 1000:
                print("Online Client: Verifying aggregated model...")
            tempCompare += rho_FinalWeight * listOfGenerators[i]

    if tempCompare.x() == int(Xvalue[0]) and tempCompare.y() == int(Xvalue[1]):
        print("Online Client: Verified! It is a valid aggregated model.")    
    else:
        print("Online Client: Aborts, not a valid aggregated model")

def get_x_w(client):
    """
    Retrieve the aggregated weight list and x values from the server.
    Algorithm 2 - Aggregation (Phase 2) - Step 6
    """
    data = client.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    send_data = "OK@"
    client.send(send_data.encode(FORMAT))
   
    rfile = client.makefile('rb')
    header = rfile.read(4)
    datalen, = struct.unpack('!L', header)
    data_bytes = rfile.read(datalen*32+datalen-1)
    finalAggregatedWeightList = data_bytes.decode('utf-8').split(',')
    finalWeightListAggregated = [int(x, 2) for x in finalAggregatedWeightList]

    send_data = "OK@"
    client.send(send_data.encode(FORMAT))
   
    x_X = client.recv(SIZE)
    x1 = struct.unpack(f"!{len(x_X)}s", x_X)
    x_xValue = x1[0].decode('utf-8')

    send_data1 = "OK@"
    client.send(send_data1.encode(FORMAT)) 
    
    x_Y = client.recv(SIZE)
    x2 = struct.unpack(f"!{len(x_Y)}s", x_Y)
    x_yValue = x2[0].decode('utf-8')

    send_data1 = "OK@"
    client.send(send_data1.encode(FORMAT)) 

    Xvalue.append(x_xValue)
    Xvalue.append(x_yValue)

    return finalWeightListAggregated

def sendingToServer(client, cm, sigServer, commitmentUse):
    """
    Send the masked updates, signatures, and commitment (if used) to the server.
    """
    client.sendall(messageM[0])
    data = client.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")

    if commitmentUse == 1:
        if cmd == "OK":
            commitmentX = str(cm.x())
            commitmentY = str(cm.y())
            commitmentXbyte = commitmentX.encode('utf-8')
            commitmentYbyte = commitmentY.encode('utf-8')
            commitment_X = struct.pack(f"!{len(commitmentXbyte)}s", commitmentXbyte)
            commitment_Y = struct.pack(f"!{len(commitmentYbyte)}s", commitmentYbyte)

            client.send(commitment_X)
            data = client.recv(SIZE).decode(FORMAT)
            cmd, msg = data.split("@")
            client.send(commitment_Y)
            data = client.recv(SIZE).decode(FORMAT)
            cmd, msg = data.split("@")

    if cmd == "OK":
        client.send(sigServer)
        data = client.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")

def sendingToAN(listOfAssistantNodeconnections, sigAssistingNodes, messageMPrime):
    """
    Send the masked updates and signatures to assistant nodes.
    """
    for i in range(len(listOfAssistantNodeconnections)):
        clientAssistant = listOfAssistantNodeconnections[i]

        command = "Agg" + "@."
        clientAssistant.send(command.encode(FORMAT))
        data = clientAssistant.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        clientAssistant.send(messageMPrime) #sending 
        data = clientAssistant.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")

        if cmd == "OK":    
            clientAssistant.send(sigAssistingNodes) #sending            
            data = clientAssistant.recv(SIZE).decode(FORMAT)
            cmd, msg = data.split("@")
            
def sendingSigofMaskingUpdates(client, listOfAssistantNodeconnections, sigAssistingNodes, messageMPrime, sigServer, cm, User_ID, NumberOfUsers, commitmentUse):
    """
    Send the masked updates and signatures to both the server and assistant nodes.
    Algorithm 2 - Aggregation (Phase 1) - Step 3
    """    
    if int(User_ID) == int(NumberOfUsers):
        print("Client: Sending Masking Updates and Sig for Server...")
    sendingToServer(client, cm, sigServer, commitmentUse)

    if int(User_ID) == int(NumberOfUsers):
        print("Client: Sending Masking Updates and Sig for AssistantNodes...")
    sendingToAN(listOfAssistantNodeconnections, sigAssistingNodes, messageMPrime)

def aggOfLists(aVector, NumOfAN, type):
    """
    Perform aggregation of lists.
    """    
    file_path2 = os.path.join(parent_dir, "aggregation.so")
    lib = cdll.LoadLibrary(file_path2) # Load the external C code
    lib.add_one.argtypes = [POINTER(POINTER(c_long)), c_long, c_long]
    lib.add_one.restype = POINTER(c_long)  # Define the return type for the C function

    rows = NumOfAN
    num_rows = len(aVector)
    num_cols = len(aVector[0])
    templist = [[0 for j in range(num_cols)] for i in range(num_rows)]

    # Check format
    for i in range(len(aVector)):
        for j in range(len(aVector[0])):
            if type == 0:
                templist[i][j] = int(aVector[i][j],2)
            else:
                templist[i][j] = aVector[i][j]

    # Convert the Python list to a C-compatible array
    arr_ptr = (POINTER(c_long) * rows)()
    for i in range(rows):
        arr_ptr[i] = (c_long * WEIGHTLISTSIZE)(*templist[i])

    # Perform the aggregation using the C code
    startAggTime = time.time()  
    new_arr_ptr = lib.add_one(arr_ptr, rows, WEIGHTLISTSIZE)
    endAggTime = time.time()  

    # Convert the result back to a Python list
    result = [new_arr_ptr[i] for i in range(WEIGHTLISTSIZE)]
    
    aggTime = endAggTime - startAggTime

    return result, aggTime

def callCcode(key_base64):
    """
    Call C++ code to perform AES encryption in CTR mode.
    """
    cpp_executable = os.path.join(parent_dir, ".", "AesModeCTR")
    input_data = key_base64.encode()
    process = subprocess.Popen(cpp_executable, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    output, error = process.communicate(input_data)
    output_str = output.decode('utf-8')

    lines = output_str.strip().splitlines()
    maskAlfaTime = lines[-1]
    lines.pop()

    hex_values = []
    binary_mask_values = []

    # Convert the output from hex to binary
    for line in lines:
        hex_values.extend(line.split())

    for hex_value in hex_values:
        hex_int = int(str(hex_value), 16)
        binary_str = format(hex_int, '032b')
        binary_mask_values.append(binary_str)

    if error:
        error_str = error.decode('utf-8')
        print("Error occurred:")
        print(error_str)

    return maskAlfaTime, binary_mask_values

def computeMaskValue():
    """
    Compute the mask values for secure aggregation using PRF and AES.
    Algorithm 2 - Aggregation (Phase 1) - Step 1
    """    
    total = 0
    bVector = []

    for i in range(len(AssistantNodeIDList)):
        byte_key = assistantNodeSharedSecretDict[AssistantNodeIDList[i]]
        key_base64 = base64.b64encode(byte_key).decode('utf-8')
        decoded_bytes = base64.b64decode(key_base64)
        maskAlfaTime, binary_mask_values = callCcode(key_base64)
        bVector.append(binary_mask_values)

    # Aggregate the mask values using C
    total, aggTimePRF = aggOfLists(bVector, len(AssistantNodeIDList),0)
    total_0 = total[0]

    return total, total_0, maskAlfaTime, aggTimePRF

def getWeightList():
    """
    Get the trained model weight list.
    """    
    weightList = [2] * WEIGHTLISTSIZE
    return weightList

def curveInfo():
    """
    Return the elliptic curve parameters for secp256k1.
    """    
    p = 115792089237316195423570985008687907853269984665640564039457584007908834671663 # Curve bsae field
    a = 0 # Curve coefficient a
    b = 7 # Curve coefficient b
    curve_1 = CurveFp(p, a, b) # Define the elliptic curve
    h_x = 56193167961224325557053041404644322304275828303249957102234782382884055918593
    h_y = 19073509862472175270077542735739351864502962599188443395223956996042974952935
    h = Point(curve_1, h_x, h_y) # Generator
    return h

def computeCommitment(weightList, total_0):
    """
    Compute the commitment for the given weight list.
    Algorithm 2 - Aggregation (Phase 1) - Step 2
    """
    listOfGenerators = []
    curve = ecdsa.SECP256k1
    generator = curve.generator

    x = int(generator.x())
    y = int(generator.y())

    secondpart = Point(None, None, None)
    listofTimes = []
    
    # Compute the second part of the commitment
    for i in range(WEIGHTLISTSIZE):
        rho_weight = rhoList[0] * weightList[i]           
        newGenerator = generator * (135351+i)
        listOfGenerators.append(newGenerator)

        start100 = time.time()
        secondpart += (newGenerator * rho_weight)        
        end100 = time.time()
        listofTimes.append(end100-start100)
    
    ecMultTime = sum(listofTimes)
    h = curveInfo()

    # Compute the first part of the commitment and combine both parts
    start10 = time.time()
    FirstPart = h * total_0
    cm = FirstPart + secondpart # line 2 - Aggregation phase (Round 1)
    end10 = time.time()
    timeForCM = end10 - start10

    return ecMultTime, timeForCM, cm, listOfGenerators

def nComputeMaskedWeight(weightList, iterationNumber, total):
    """
    Compute the masked weight list for secure aggregation.
    Algorithm 2 - Aggregation (Phase 1) - Step 1
    """
    maskedWeightList = []
    cVector = []
    cVector.append(weightList)
    cVector.append(total)

    # Aggregate the masked weight list using C
    yList, aggTimeY = aggOfLists(cVector, len(cVector), 1)

    for y in yList:
        binMaskedWeight = bin(y)[2:]
        if len(binMaskedWeight) > 32:
            binMaskedWeight = binMaskedWeight[-32:]
        maskedWeightList.append(binMaskedWeight)

    finalMaskedWeightList = []
    finalMaskedWeightList = [element.rjust(32, '0') for element in maskedWeightList]
    finalMaskedWeightList_byte = ','.join(finalMaskedWeightList).encode('utf-8')

    messageM.append(struct.pack(f'!L{len(finalMaskedWeightList_byte)}s', len(weightList), finalMaskedWeightList_byte))
    messageMPrime = struct.pack('l',iterationNumber)

    return finalMaskedWeightList, messageMPrime, aggTimeY

def generatingSignature(finalMaskedWeightList, private_key_sign, cm, messageMPrime):
    """
    Generate the signature for the masked weight list and commitment.
    Algorithm 2 - Aggregation (Phase 1) - Step 3
    """
    strForSig = str(finalMaskedWeightList) + str(cm.x()) + str(cm.y())
    mystr = strForSig.encode('utf-8')
    
    startAggTimeMaliciousSetting = time.time()
    messageMForSigHash = hashlib.sha256(mystr).hexdigest()
    sigServer = private_key_sign.sign(messageMForSigHash.encode('utf-8'))
    sigAssistingNodes = private_key_sign.sign(messageMPrime)
    endAggTimeMaliciousSetting = time.time()

    aggTimeMaliciousSetting = endAggTimeMaliciousSetting - startAggTimeMaliciousSetting

    return sigServer, sigAssistingNodes, aggTimeMaliciousSetting

def train_model(client, private_key_sign, User_ID, NumberOfUsers, commitmentUse):
    """
    Get the trained model weights and compute masked weights, generate signatures, and sending data to the server.
    Algorithm 2 - Aggregation (Phase 1) - Step 1 & 2 & 3
    """
    command = "train" + "@."
    client.send(command.encode(FORMAT))
    data = client.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    
    iterationNumber = getIterationNumber()
    total, total_0, maskAlfaTime, aggTimePRF = computeMaskValue() #a
    
    maskAlfaGen = maskAlfaTime.split()
    maskAlfaGenTime = maskAlfaGen[0]
    computeMaskValueTime = ((aggTimePRF)) * 10**3 + (int(maskAlfaGenTime) / 1000000)

    weightList = getWeightList()

    if commitmentUse == 1:
        if int(User_ID) == int(NumberOfUsers):
            print("Client: Computing commitment...")
        ecMultTime, timeForCM, cm, listOfGenerators = computeCommitment(weightList, total_0)
    else:
        listOfGenerators = []
        cm = Point(None, None, None)

    if int(User_ID) == int(NumberOfUsers):
        print("Client: Computing masked weight...")

    finalMaskedWeightList, messageMPrime, aggTime2 = nComputeMaskedWeight(weightList, iterationNumber, total)
        
    TotalTime = ((aggTime2) * 10**3) + computeMaskValueTime

    sigServer, sigAssistingNodes, aggTimeMaliciousSetting = generatingSignature(finalMaskedWeightList, private_key_sign, cm, messageMPrime)
    
    if commitmentUse == 1 and int(User_ID) == int(NumberOfUsers):
        commitmentGenTime.append(ecMultTime + timeForCM)
    
    return sigServer, sigAssistingNodes, messageMPrime, TotalTime, aggTimeMaliciousSetting, cm, listOfGenerators

def agree(private_key, AssistantNodePublicKey, User_ID, NumberOfUsers):
    """
    Compute the shared secrets between the user and all assistant nodes.
    """
    if int(User_ID) == int(NumberOfUsers):
        start_setup = time.time()

    Xpa = private_key.ecdh(AssistantNodePublicKey) # Computing shared secret seed

    if int(User_ID) == int(NumberOfUsers):
        end_setup = time.time()
        executionTime.append(end_setup-start_setup)

    return Xpa

def computeXpa(private_key, User_ID, NumberOfUsers, commitmentUse):
    """
    Compute the shared secrets between the user and all assistant nodes.
    Algorithm 1 - Setup (Phase 1) - Step 4 & 6
    """
    for i in range(1, len(assistantNodePublicKeyDict)+1):
        Xpa = agree(private_key, assistantNodePublicKeyDict[str(i)], User_ID, NumberOfUsers) # Compute shared secret seed
        assistantNodeSharedSecretDict[str(i)] = Xpa
        
        # If commitment is used, decrypt rho.
        if commitmentUse == 1 and i == len(assistantNodePublicKeyDict):
            decryptTimeStart = time.time()
            box = nacl.secret.SecretBox(Xpa)
            rho = box.decrypt(listOfEncryptedValue[0])
            decryptTimeEnd = time.time()
            rhoList.append(int(rho))
            decryptTime = decryptTimeEnd - decryptTimeStart
            decryptionTimeSetup.append(decryptTime)

def connectToAssistantNodeAndAdvertise(clientAssistant, public_key_sign, public_key, AssistantNodeID, NumberOfANs, commitmentUse):
    """
    Advertise public keys, and receive the assistant node's public keys.
    Algorithm 1 - Setup (Phase 1) - Step 1
    """    
    twoKeys = struct.pack('33s 33s', public_key_sign.format(), public_key.format())
    clientAssistant.send(twoKeys) # Send public_keys to Assisting Nodes.

    AN_PKs = clientAssistant.recv(SIZE) # Receive public_keys from Assistant Node.
    twoKeysFromAssistantNode = struct.unpack(('33s 33s'), AN_PKs)
    AssistantNodePublicKeySign = twoKeysFromAssistantNode[0]
    AssistantNodePublicKey = twoKeysFromAssistantNode[1]
    
    if commitmentUse == 1 and AssistantNodeID == str(NumberOfANs):
        send_data = "OK@"
        clientAssistant.send(send_data.encode(FORMAT)) 
        encryptedValue = clientAssistant.recv(SIZE) #Cpa
        listOfEncryptedValue.append(encryptedValue)
        
    return AssistantNodePublicKey

def handleAssistantNode(public_key_sign, ADDR, AssistantNodeID, public_key, NumberOfANs, commitmentUse):
    """
    Handle connection to an assistant node.
    """    

    clientAssistant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientAssistant.connect(ADDR)    

    AssistantNodePublicKey = connectToAssistantNodeAndAdvertise(clientAssistant, public_key_sign, public_key, AssistantNodeID, NumberOfANs, commitmentUse)
    assistantNodePublicKeyDict[AssistantNodeID] = AssistantNodePublicKey
    listOfAssistantNodeconnections.append(clientAssistant)

def connectToANAndAdvertise(NumberOfActiveAssistantNodes, public_key_sign, private_key, public_key, NumberOfANs, commitmentUse):
    """
    Connect to all assistant nodes, initiate key exchange, and compute shared secrets.
    """    
    AN_threads = []
    AssistantNodePort = Lines[1].strip().split("=")[1].strip()

    # Create connection and initiate key exchange with each assistant node
    for i in range(1, NumberOfANs+1):
        PORT2 = int(AssistantNodePort)+i-1
        ADDR = (IP, PORT2)
        ADDRlist.append(ADDR)
        AssistantNodeIDList.append(str(i))
        NumberOfActiveAssistantNodes += 1

    for i in range(1, NumberOfANs+1):
        t = threading.Thread(target=handleAssistantNode, args=(public_key_sign, ADDRlist[i-1], AssistantNodeIDList[i-1], public_key, NumberOfANs, commitmentUse))
        AN_threads.append(t)
    
    for i in range(1, NumberOfANs+1):
        AN_threads[i-1].start()
    for i in range(1, NumberOfANs+1):
        AN_threads[i-1].join()
        
def connectToServerAndAdvertise(client, input_argv, public_key_sign):
    """
    Connect to the server, advertise the public key, and receive the server's public key.
    """
    data = client.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")    
    
    if cmd == "OK":
        client.send(str(input_argv).encode('latin1'))
    
        data = client.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        
        if cmd == "OK":
            client.send(public_key_sign.format()) # Send public_key_sign to the Server.
            serverPublicKeySign = client.recv(SIZE) # Receive the server's public_key_sign.

def getIterationNumber():
    return 137    

def KeyGen():
    """
    Generate a key pair.
    Algorithm 1 - Setup (Phase 1) - Step 1
    """    
    start_setup_phase_malicous_setting = time.time()
    private_key_sign = PrivateKey()
    public_key_sign = private_key_sign.public_key
    end_setup_phase_malicous_setting = time.time()
    timeMaliciousSetting = end_setup_phase_malicous_setting - start_setup_phase_malicous_setting

    start_setup_phase1 = time.time()
    private_key = PrivateKey()
    public_key = private_key.public_key
    end_setup_phase1 = time.time()
    keyGenTime = end_setup_phase1-start_setup_phase1

    return private_key_sign, public_key_sign, private_key, public_key, keyGenTime, timeMaliciousSetting

def main():
    """
    Main function to initialize the client, handle connections, and perform secure aggregation.
    """
    # Parse command-line arguments
    User_ID = str(sys.argv[1])
    NumberOfUsers = int(sys.argv[2])
    NumberOfANs = int(sys.argv[3])
    commitmentUse = int(sys.argv[4]) # 0 = without commiment & 1 = with commitment
    input_argv = 1

    # Generate the key
    private_key_sign, public_key_sign, private_key, public_key, keyGenTime, timeMaliciousSetting = KeyGen()
    setupPhaseComputationTime1 = keyGenTime

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    # Manage connections
    connectToServerAndAdvertise(client, input_argv, public_key_sign)
    NumberOfActiveAssistantNodes = 0
    connectToANAndAdvertise(NumberOfActiveAssistantNodes, public_key_sign, private_key, public_key, NumberOfANs, commitmentUse)
    
    # Compute shared secrets
    computeXpa(private_key, User_ID, NumberOfUsers, commitmentUse)

    if int(User_ID) == int(NumberOfUsers):
        print("Client: Setup phase finished.")

    # Compute the masked weight 
    sigServer, sigAssistingNodes, messageMPrime, aggTime, aggTimeMaliciousSetting, cm, listOfGenerators = train_model(client, private_key_sign, User_ID, NumberOfUsers, commitmentUse)

    printResults(User_ID, NumberOfUsers, timeMaliciousSetting, setupPhaseComputationTime1, aggTimeMaliciousSetting, aggTime, commitmentUse)

    finalWeightList = sendingSigofMaskingUpdates(client, listOfAssistantNodeconnections, sigAssistingNodes, messageMPrime, sigServer, cm, User_ID, NumberOfUsers, commitmentUse)

    if int(User_ID) == int(NumberOfUsers) and commitmentUse == 1:
        finalWeightListAggregated = get_x_w(client)
        validateAggregatedModel(finalWeightListAggregated, listOfGenerators)

if __name__ == "__main__":
    main()
