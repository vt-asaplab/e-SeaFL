import socket
import struct
import threading
import time
import random
import sys
import nacl.secret
import nacl.utils
import hashlib
import base64
import subprocess
from ctypes import cdll, c_long, POINTER
from coincurve.keys import PrivateKey
from coincurve.utils import verify_signature
import os

# Configuration
IP = "127.0.0.1" # Server IP address
FORMAT = "utf-8" # Encoding format
SIZE = 4096 # Buffer size for socket communication
WEIGHTLISTSIZE = 16000 # Size of the weight list for aggregation

# Load server port from configuration file
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
file_path = os.path.join(parent_dir, "port.txt")
PortFile = open(file_path, 'r')
Lines = PortFile.readlines()   
ServerPort = Lines[0].strip().split("=")[1].strip()

PORT = int(ServerPort)
ADDR = (IP, PORT) # Server address tuple (IP, Port)

# Global variables used throughout the code
userlist = [] # List to store verified users
sigmaValue = 0
verTime = [] # List to store verification times
clientDictConnAddr = {} # Dictionary to store client connections by address
clientDict = {} # Dictionary to store client public keys
clientDictInformation = {} # Dictionary to store client information
clientDictForXpa = {} # Dictionary to store shared secrets
executionTime = [] # List to store execution times for shared secrets
listofClientAddress = [] # List to store client addresses
messageMdoublePrime = [] # List to store masked updates
outboundBandWidth = [] # List to store outbound bandwidth

def printResults(timeMaliciousSetting, computeMaskValueTime, totalTime, setupPhaseComputationTime, aggTime1):
    """
    Print the setup and aggregation times.
    """
    print("\n==== Assisting Node RESULTS ====")
    sumOfcomputingSecretSeed = sum(executionTime)  
    setupPhaseComputationTime += sumOfcomputingSecretSeed
    print("AN: Semi-Honest Setting (Setup Phase):",(setupPhaseComputationTime) * 10**3, "ms")
    print("AN: Malicious Setting (Setup Phase):",(setupPhaseComputationTime + timeMaliciousSetting) * 10**3, "ms")        
    print("AN: Semi-Honest Setting (Aggregation Phase):",(computeMaskValueTime), "ms")
    print("AN: Malicious Setting (Aggregation Phase):",(totalTime + aggTime1), "ms")
    print("===============================")

def printOutboundBandwidth():
    """
    Print the outbound bandwidth.
    """
    print("============================================")
    print("**** Assisting Node OUTBOUND BANDWIDTH ****")
    print("AN: Semi-Honest Setting (Setup Phase):", outboundBandWidth[0], "B")
    print("AN: Malicious Setting (Setup Phase):", outboundBandWidth[1], "B")
    print("AN: Semi-Honest Setting (Aggregation Phase):",outboundBandWidth[2], "B")
    print("AN: Malicious Setting (Aggregation Phase):",outboundBandWidth[3], "B")        
    print("============================================\n")

def commitmentMode(commitmentUse, AssistantNode_ID, NumberOfANs):
    if commitmentUse == 1 and int(AssistantNode_ID) == NumberOfANs:
        rho = rhoComputation()
    else:
        rho = 0
    return rho

def callCcode(key_base64):
    """
    Call C++ code to perform AES encryption in CTR mode.
    """    
    cpp_executable = os.path.join(parent_dir,".", "AesModeCTR")
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

def aggOfLists(aVector, NumOfAN, type):    
    """
    Perform aggregation of lists using C.
    """    
    file_path2 = os.path.join(parent_dir, "aggregation.so")
    lib = cdll.LoadLibrary(file_path2) # Load the external C code
    lib.add_one.argtypes = [POINTER(POINTER(c_long)), c_long, c_long]
    lib.add_one.restype = POINTER(c_long) # Define the return type for the C function
    
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

def computeMaskValue():
    """
    Compute the mask values for secure aggregation using PRF and AES.
    Algorithm 2 - Aggregation (Phase 2) - Step 2    
    """    
    total = 0
    bVector = []

    if len(userlist) > sigmaValue:        
        for i in range(len(userlist)):
            byte_key = clientDictForXpa[int(userlist[i])]
            key_base64 = base64.b64encode(byte_key).decode('utf-8')
            maskAlfaTime, binary_mask_values = callCcode(key_base64)
            bVector.append(binary_mask_values)
            
        total, aggTimePRF = aggOfLists(bVector, len(userlist),0) #callToCompute_a

    return total, maskAlfaTime, aggTimePRF

def sendingToServer(AssistantNode, sigServer, iterationNumber, total_0):
    """
    Send the masked updates and signature to the server.
    Algorithm 2 - Aggregation (Phase 2) - Step 2    
    """    
    AssistantNode.sendall(messageMdoublePrime[0])
    data = AssistantNode.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")

    messageMPrime_I_L = struct.pack('l l l',iterationNumber, len(userlist), total_0)

    AssistantNode.send(messageMPrime_I_L)
    data = AssistantNode.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")

    AssistantNode.send(sigServer)

def checkThreshold(AssistantNode, private_key_sign, AssistantNode_ID, NumberOfANs, iterationNumber):
    """
    Compute the masked updates and the signature, and send them to the server.
    Algorithm 2 - Aggregation (Phase 2) - Step 2
    """
    totalList = []
    finalMaskedValue = []
    
    command = "checkdelta" + "@."
    AssistantNode.send(command.encode(FORMAT))
    data = AssistantNode.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    
    total, maskAlfaTime, aggTimePRF = computeMaskValue() #a

    maskAlfaGen = maskAlfaTime.split()
    maskAlfaGenTime = maskAlfaGen[0]
    computeMaskValueTime = ((aggTimePRF)) * 10**3 + (int(maskAlfaGenTime) / 1000000)

    total_0 = total[0]

    for y in total:
        binMaskedWeight = bin(y)[2:]
        if len(binMaskedWeight) > 32:
            binMaskedWeight = binMaskedWeight[-32:]
        totalList.append(binMaskedWeight)

    finalMaskedValue = [element.rjust(32, '0') for element in totalList]
    finalMaskedValue_byte = ','.join(finalMaskedValue).encode('utf-8')

    messageMdoublePrime.append(struct.pack(f'!L{len(finalMaskedValue_byte)}s', len(total), finalMaskedValue_byte))

    startAggTimeMaliciousSetting = time.time()
    strForSig = str(finalMaskedValue) + str(iterationNumber) + str(len(userlist))
    mystr = strForSig.encode('utf-8')
    messageMdoyblePrimeForSigHash = hashlib.sha256(mystr).hexdigest()
    sigServer = private_key_sign.sign(messageMdoyblePrimeForSigHash.encode('utf-8'))
    endAggTimeMaliciousSetting = time.time()

    aggTimeMaliciousSetting = endAggTimeMaliciousSetting - startAggTimeMaliciousSetting
    
    sendingToServer(AssistantNode, sigServer, iterationNumber, total_0)  

    finalMaskedInts = [int(element, 2) for element in finalMaskedValue]
    data_size = struct.pack(f'{len(finalMaskedInts)}I', *finalMaskedInts)
    list_size = struct.pack('i', len(userlist))
    t_size = struct.pack('i', iterationNumber)
    outboundBandWidth.append(len(data_size) + len(list_size) + len(t_size))
    outboundBandWidth.append(len(data_size) + len(list_size) + len(t_size) + len(sigServer))

    totalTime = computeMaskValueTime + ((aggTimeMaliciousSetting) * 10**3)
    return computeMaskValueTime, totalTime

def verifySigofUsers():
    """
    Verify the signatures of users.
    Algorithm 2 - Aggregation (Phase 2) - Step 1
    """    
    for i in range (0, len(clientDict)):
        start1 = time.time()
        verify = verify_signature(clientDictInformation[listofClientAddress[i]][1], clientDictInformation[listofClientAddress[i]][0], clientDict[listofClientAddress[i]][0])
        end1 = time.time()
        
        if (str(verify) == "True"):
            userlist.append(listofClientAddress[i])

        verifyTime = end1 - start1
        verTime.append(verifyTime)

    iterationNumberList = struct.unpack(('l'), clientDictInformation[listofClientAddress[0]][0])
    iterationNumber = iterationNumberList[0]
    return iterationNumber, sum(verTime)

def agree(private_key,clientPublicKey,AssistantNode_ID,NumberOfANs,type):
    if int(AssistantNode_ID) == NumberOfANs and type == 0:
        start_setup_phase2 = time.time()
    
    Xpa = private_key.ecdh(clientPublicKey) # Computing shared secret seed

    if int(AssistantNode_ID) == NumberOfANs and type == 0:
        end_setup_phase2 = time.time()
        executionTime.append(end_setup_phase2-start_setup_phase2)
    
    return Xpa

def computeXpa(private_key, AssistantNode_ID, NumberOfANs):
    """
    Compute the shared secrets between the assistant node and all clients.
    Algorithm 1 - Setup (Phase 1) - Step 3
    """    
    for address in listofClientAddress:
        Xpa = agree(private_key, clientDict[address][1], AssistantNode_ID,NumberOfANs,0) # Computing shared secret seed
        clientDictForXpa[address] = Xpa

def ciphertextComputation(Xpa, rho):
    """
    Encrypt the value rho using the shared secret Xpa.
    Algorithm 1 - Setup (Phase 1) - Step 5    
    """    
    box = nacl.secret.SecretBox(Xpa)
    message = str(rho).encode()
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(message, nonce) # Line 5 in setup
    return ciphertext

def rhoComputation():
    """
    Generate a random value rho for commitment.
    Algorithm 1 - Setup (Phase 1) - Step 5
    """    
    rho = random.randint(0, 2**256-1)
    return rho

def connectToClientAndAdvertise(conn, addr, public_key_sign, public_key, address, NumberOfANs, commitmentUse, AssistantNode_ID, private_key, rho):
    """
    Connect to a client, exchange public keys, and perform encryption if commitment is used.
    Algorithm 1 - Setup (Phase 1) - Step 3 & 5    
    """    
    client_PKs = conn.recv(SIZE) # Receive public_keys from users
    twoKeysFromClient = struct.unpack(('33s 33s'), client_PKs)

    clientPublicKeySign = twoKeysFromClient[0]
    clientPublicKey = twoKeysFromClient[1]
    clientDict[address[1]] = clientPublicKeySign, clientPublicKey

    twoKeys = struct.pack('33s 33s', public_key_sign.format(), public_key.format())
    conn.send(twoKeys) # Send public_keys to users       

    listofClientAddress.append(addr[1])

    # If commitment is used, perform encryption
    if commitmentUse == 1 and int(AssistantNode_ID) == NumberOfANs:
        data = conn.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        Xpa = agree(private_key, clientDict[addr[1]][1], AssistantNode_ID,NumberOfANs,1)
        Cpa = ciphertextComputation(Xpa, rho) # Encrypt rho using the shared secret
        conn.send(Cpa)

    return clientPublicKey

def handle_User(conn, addr, public_key_sign, private_key, public_key, AssistantNode_ID, NumberOfANs,rho, commitmentUse):
    """
    Handle communication and data exchange with a client.
    """

    clientDictConnAddr[addr[1]] = conn
    clientPublicKey = connectToClientAndAdvertise(conn, addr, public_key_sign, public_key, addr, NumberOfANs, commitmentUse, AssistantNode_ID, private_key, rho)

    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        cmd = data.split("@")    
        if cmd[0] == "Agg":
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 

            messageMPrimeofMaskingUpdates = conn.recv(SIZE)
            send_data = "OK@"

            conn.send(send_data.encode(FORMAT)) 
            sigForMaskingUpdates = conn.recv(SIZE)

            send_data = "OK@AN: Message M prime and Sig received."
            conn.send(send_data.encode(FORMAT)) 

            clientDictInformation[addr[1]] = messageMPrimeofMaskingUpdates, sigForMaskingUpdates
            break
        else:
            continue

def manageIncomingConnections(AssistantNode_ID, public_key_sign, private_key, public_key, NumberOfUsers,NumberOfANs, rho, commitmentUse):
    """
    Manage incoming connections from clients and handle communication.
    """
    temp = Lines[1].strip().split("=")[1].strip()
    AssistantNodePort = int(temp) + int(AssistantNode_ID) - 1
    PORT2 = AssistantNodePort
    ADDR2 = (IP, PORT2)

    Assistant = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Assistant.bind(ADDR2)
    Assistant.listen(4096)

    total_connections = NumberOfUsers
    user_threads = []
    connections_accepted = 0

    # Accept connections from clients
    while connections_accepted < total_connections:
        conn, address = Assistant.accept()

        user_thread = threading.Thread(target=handle_User, args=(conn, address, public_key_sign, private_key, public_key, AssistantNode_ID,NumberOfANs,rho,commitmentUse,))  
        user_thread.start()
        user_threads.append(user_thread)

        connections_accepted += 1

    for user_thread in user_threads:
        user_thread.join()

    return Assistant

def connectToServerAndAdvertise(AssistantNode, input_argv, public_key_sign):
    """
    Connect to the server and advertise the public key.
    Algorithm 1 - Setup (Phase 1) - Step 2
    """
    data = AssistantNode.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")    

    if cmd == "OK":
        AssistantNode.send(str(input_argv).encode('latin1'))
        data = AssistantNode.recv(SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        if cmd == "OK":
            AssistantNode.send(public_key_sign.format()) # Send public_key_sign to the server
       
def KeyGen():
    """
    Generate a key pair.
    Algorithm 1 - Setup (Phase 1) - Step 2
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
    Main function to initialize the assistant node, handle connections, and perform secure aggregation.
    """
    AssistantNode_ID = str(sys.argv[1])
    NumberOfUsers = int(sys.argv[2])
    NumberOfANs = int(sys.argv[3])
    commitmentUse = int(sys.argv[4]) # 0 = without commiment & 1 = with commitment
    bandwidthPrint = int(sys.argv[5])
    input_argv = 2

    # Generate the key
    private_key_sign, public_key_sign, private_key, public_key, keyGenTime, timeMaliciousSetting = KeyGen()
    setupPhaseComputationTime = keyGenTime
    public_key_bytes = public_key.format(compressed=True)
    public_key_bytes2 = public_key_sign.format(compressed=True)
    outboundBandWidth.append(len(public_key_bytes) * NumberOfUsers)
    outboundBandWidth.append(((len(public_key_bytes2) + len(public_key_bytes)) * NumberOfUsers) + len(public_key_bytes2))

    rho = commitmentMode(commitmentUse, AssistantNode_ID, NumberOfANs)
        
    AssistantNode = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    AssistantNode.connect(ADDR)

    # Manage connections
    connectToServerAndAdvertise(AssistantNode, input_argv, public_key_sign)
    AssistantSocket = manageIncomingConnections(AssistantNode_ID, public_key_sign, private_key, public_key, NumberOfUsers,NumberOfANs, rho, commitmentUse)

    # Compute shared secrets
    computeXpa(private_key, AssistantNode_ID, NumberOfANs)
    AssistantSocket.close()

    if int(AssistantNode_ID) == NumberOfANs:
        print("AN: Setup phase finished.")
        print("AN: Awaiting all clients to send their results for ANs...")
    
    iterationNumber, aggTime1 = verifySigofUsers()
    computeMaskValueTime, totalTime = checkThreshold(AssistantNode, private_key_sign, AssistantNode_ID, NumberOfANs, iterationNumber)

    if int(AssistantNode_ID) == NumberOfANs:
        if bandwidthPrint == 0:
            printResults(timeMaliciousSetting, computeMaskValueTime, totalTime, setupPhaseComputationTime, aggTime1)
            print("")
        elif bandwidthPrint == 1:
            # Print both results and outbound bandwidth
            printResults(timeMaliciousSetting, computeMaskValueTime, totalTime, setupPhaseComputationTime, aggTime1)
            print("")
            printOutboundBandwidth()
        else:
            # Print only the outbound bandwidth
            print("")
            printOutboundBandwidth()

if __name__ == "__main__":
    main()
