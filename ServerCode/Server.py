import socket
import struct
import threading
import time
import sys
import hashlib
from ctypes import cdll, c_long, POINTER
from ecdsa.ellipticcurve import CurveFp, Point
from pprint import pprint
import os

from coincurve.keys import PrivateKey
from coincurve.utils import verify_signature

# Configuration
IP = "127.0.0.1" # Server IP address
FORMAT = "utf-8" # Encoding format
SIZE = 256000 # Buffer size for socket communication
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
userlist = [] # List to store user IDs that are successfully verified
AssistantNodelist = [] # List to store assistant node IDs
clientDict = {} # Dictionary to map client addresses to their public keys
clientDictInformation = {} # Dictionary to map client addresses to their masked updates and signatures
assistantNodeDict = {} # Dictionary to map assistant node addresses to their public keys
AssistantNodeDictInformation = {} # Dictionary to map assistant node addresses to their masked updates and signatures
listOfUserInAssistantNodes = [] # List to store the number of users handled by each assistant node
listOfmaskedUpdatesInAssistantNodes = [] # List to store masked updates from assistant nodes
listOfyInclient = [] # List to store masked updates from users
listofClientAddress = [] # List to store client addresses
cmDict = {} # Dictionary to map client addresses to their commitments (x, y coordinates)
xListValues = []  # List to store x elliptic curve points
FinalWeightList = [] # List to store the final aggregated weight list
total_0 = [] # List to store a[0] from assistant nodes
cmAggTime = [] # List to store the aggregation times of commitments
outboundBandWidth = [] # List to store outbound bandwidth

def printResults(aggTime1, aggTime2, aggTime3, keyGenTime, ver_user_time, ver_AN_time, commitmentUse):
    """
    Print the setup and aggregation times.
    """
    totalAggTime = aggTime1 + aggTime2 + aggTime3    
    print("Server: Aggregation phase finished.")
    print("\n==== Server RESULTS ====")
    print("Server: Semi-Honest Setting (Setup Phase): 0 ms")
    print("Server: Malicious Setting (Setup Phase):",(keyGenTime) * 10**3, "ms")    
    print("Server: Semi-Honest Setting (Aggregation Phase):",(totalAggTime) * 10**3, "ms")
    print("Server: Malicious Setting (Aggregation Phase):",(totalAggTime + ver_user_time + ver_AN_time) * 10**3, "ms")
    if commitmentUse == 1:
        print("Server: Commitment Aggregation Time",(cmAggTime[0]) * 10**3, "ms")
    print("========================")

def printOutboundBandwidth():
    """
    Print the outbound bandwidth.
    """
    print("===================================")
    print("**** Server OUTBOUND BANDWIDTH ****")
    print("Server: Semi-Honest Setting (Setup Phase): 0 B")
    print("Server: Malicious Setting (Setup Phase):", outboundBandWidth[0], "B")
    print("Server: Semi-Honest Setting (Aggregation Phase):",outboundBandWidth[1], "B")
    print("Server: Malicious Setting (Aggregation Phase):",outboundBandWidth[2], "B")        
    print("===================================\n")

def send_x_w(last_connection):
    """
    Send the final weight list and other necessary data to online clients.
    """
    FinalWeightListbin = []
    SendFinalWeightList = []

    # Convert each element of FinalWeightList to binary string
    for element in FinalWeightList:
        binary = bin(element)[2:]
        FinalWeightListbin.append(binary)
    
    # Ensure each binary string is 32 bits long
    FinalWeightListbin256 = [element.rjust(32, '0') for element in FinalWeightListbin]
    finalMaskedWeightList_byte = ','.join(FinalWeightListbin256).encode('utf-8')
    
    # Pack the binary data into a single message
    SendFinalWeightList.append(struct.pack(f'!L{len(finalMaskedWeightList_byte)}s', len(FinalWeightList), finalMaskedWeightList_byte))
   
    send_data = "OK@"
    last_connection.send(send_data.encode(FORMAT))
   
    data = last_connection.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    
    last_connection.sendall(SendFinalWeightList[0])
    data = last_connection.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    
    # Send additional parts of the final weight list
    last_connection.send(xListValues[0])
    data = last_connection.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    last_connection.send(xListValues[1])
    data = last_connection.recv(SIZE).decode(FORMAT)
    cmd, msg = data.split("@")
    send_data = "OK@."
    last_connection.send(send_data.encode(FORMAT))

def curveInfo():
    """
    Return the elliptic curve parameters for secp256k1.
    """
    p = 115792089237316195423570985008687907853269984665640564039457584007908834671663 # Curve bsae field
    a = 0 # Curve coefficient a
    b = 7 # Curve coefficient b
    curve = CurveFp(p, a, b) # Define the elliptic curve
    h_x = 56193167961224325557053041404644322304275828303249957102234782382884055918593
    h_y = 19073509862472175270077542735739351864502962599188443395223956996042974952935
    h = Point(curve, h_x, h_y) # Generator
    return h, curve

def computeX():
    """
    Compute the final value x using commitments and masked updates from assistant nodes.
    Algorithm 2 - Aggregation (Phase 2) - Step 5
    """    
    h, curve = curveInfo() # Get the curve and a generator
    cmList = []  
    
    # Compute the second part of x
    start1 = time.time()
    for i in range(len(listOfmaskedUpdatesInAssistantNodes)):
        if i == 0:
            secondPart = -total_0[i] * h
        else:
            secondPart_temp = -total_0[i] * h
            secondPart += secondPart_temp
    end1 = time.time()

    # Compute the first part of x
    for key in cmDict:
        x = cmDict[key][0]
        y = cmDict[key][1]
        cm = Point(curve, x, y)
        cmList.append(cm)

    start2 = time.time()
    for i in range(len(cmList)):
        if i == 0:
            firstPart = cmList[i]
        else:
            firstPart += cmList[i]

    x = firstPart + secondPart # Combine both parts to get x
    end2 = time.time()

    # Pack the coordinates of x into binary format
    x_Xbyte = str(x.x()).encode('utf-8')
    x_Ybyte = str(x.y()).encode('utf-8')
    x_X = struct.pack(f"!{len(x_Xbyte)}s", x_Xbyte)
    x_Y = struct.pack(f"!{len(x_Ybyte)}s", x_Ybyte)
    xListValues.append(x_X)
    xListValues.append(x_Y)

    cmAggTime.append((end1 - start1) + (end2 - start2))

def aggOfLists(aVector, NumOfAN, type):
    """
    Perform aggregation.
    """

    file_path2 = os.path.join(parent_dir, "aggregation.so")
    lib = cdll.LoadLibrary(file_path2) # Load the external C code
    lib.add_one.argtypes = [POINTER(POINTER(c_long)), c_long, c_long]
    lib.add_one.restype = POINTER(c_long) # Define the return type for the C function

    rows = NumOfAN
    num_rows = len(aVector)
    num_cols = len(aVector[0])
    templist = [[0 for j in range(num_cols)] for i in range(num_rows)]

    # Check format for aggregation
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

def computeFinalUpdate(printAggOutput, NumberOfUsers, private_key_sign):
    """
    Compute the final aggregated update from the masked updates and user-provided values.
    Algorithm 2 - Aggregation (Phase 2) - Step 4
    """
    a_t_A_list = []
    y_t_p_list = []

    # Aggregate masked updates from assistant nodes
    a_t_A, aggTime1 = aggOfLists(listOfmaskedUpdatesInAssistantNodes, len(AssistantNodelist),0)
    # Aggregate masked values from users
    y_t_p, aggTime2 = aggOfLists(listOfyInclient, len(userlist),0)

    # Check format of the values
    start_init = time.time()
    a_t_A_list = [(bin(y & 0xFFFFFFFF)[2:]) for y in a_t_A]
    y_t_p_list = [(bin(y & 0xFFFFFFFF)[2:]) for y in y_t_p]
    end_init = time.time()
    init_time = end_init - start_init 
    print("Server: init time:",(init_time) * 10**3, "ms")

    # Compute the final weights by subtracting aggregated values
    start = time.time()
    for i in range(0, WEIGHTLISTSIZE):
        FinalWeightValue = int(y_t_p_list[i], 2) - int(a_t_A_list[i], 2)
        if FinalWeightValue < 0:
            y_t_p_list[i] = "1" + y_t_p_list[i]
            FinalWeightValue = int(y_t_p_list[i], 2) - int(a_t_A_list[i], 2)

        FinalWeightList.append(FinalWeightValue)
    end = time.time()
    aggTime3 = end - start    

    # Print the aggregated vector based on the printAggOutput flag
    if printAggOutput == 1:
        print("Aggregated vector:", FinalWeightList) # line 4 - Aggregation phase (Round 2)
    if printAggOutput == 2:
        print("Aggregated vector:")
        pprint(FinalWeightList[:10] + ['...'] + FinalWeightList[-10:])

    data_size = struct.pack(f'{len(FinalWeightList)}i', *FinalWeightList)
    outboundBandWidth.append(len(data_size)*NumberOfUsers)
    messageMForSigHash = hashlib.sha256(data_size).hexdigest()
    signature = private_key_sign.sign(messageMForSigHash.encode('utf-8'))
    outboundBandWidth.append((len(data_size)*NumberOfUsers) + len(signature))

    return aggTime1, aggTime2, aggTime3

def checkUserListCondition(printAggOutput, NumberOfUsers, private_key_sign):
    """
    Check if the list of users is correct and perform aggregation if valid.
    Algorithm 2 - Aggregation (Phase 2) - Step 4
    """
    flag = 0
    for i in range (len(AssistantNodelist)):
        if len(userlist) == listOfUserInAssistantNodes[i]:
            None
        else:
            flag = 1
            break

    if flag == 0:
        print("Server: Aggregating...")
        aggTime1, aggTime2, aggTime3 = computeFinalUpdate(printAggOutput, NumberOfUsers, private_key_sign) # Algorithm 2 - Aggregation (Phase 2) - Step 4
    else:
        print("Server: ABORT - Some connections were lost or congested, possibly due to system resource limitations. Please try rerunning the code, check the file descriptor limits, or consider reducing the number of clients.")

        aggTime1, aggTime2, aggTime3 = 0, 0, 0

    return aggTime1, aggTime2, aggTime3, flag

def verifySigofANs():
    """
    Verify the signatures of assistant nodes.
    Algorithm 2 - Aggregation (Phase 2) - Step 4
    """
    ANverifyTime = []    
    for i in range (0, len(assistantNodeDict)):
        start = time.time()

        # Unpack and verify the message from the assistant node
        mDoublePrimeUnpack = struct.unpack(('l l l'), AssistantNodeDictInformation[AssistantNodelist[i]][1])
        strForSig = str(AssistantNodeDictInformation[AssistantNodelist[i]][0]) + str(mDoublePrimeUnpack[0]) + str(mDoublePrimeUnpack[1])
        total_0.append(mDoublePrimeUnpack[2])
        mystr = strForSig.encode('utf-8')
        messageMDoublePrimeForSigHash = hashlib.sha256(mystr).hexdigest()
        verify = verify_signature(AssistantNodeDictInformation[AssistantNodelist[i]][2], messageMDoublePrimeForSigHash.encode('utf-8'), assistantNodeDict[AssistantNodelist[i]]) # Algorithm 2 - Aggregation (Phase 2) - Step 4

        end = time.time()
        verifyTime = end - start
        ANverifyTime.append(verifyTime)

        if (str(verify) == "True"):
            listOfUserInAssistantNodes.append(mDoublePrimeUnpack[1])
            listOfmaskedUpdatesInAssistantNodes.append(AssistantNodeDictInformation[AssistantNodelist[i]][0])
        else:
            print("SERVER: ABORT, Run One More Time")
            break

    return sum(ANverifyTime)

def verifySigofUsers():
    """
    Verify the signatures of users
    Algorithm 2 - Aggregation (Phase 2) - Step 3
    """
    userVerifyTime = []    
    for i in range (0, len(clientDict)):
        start1 = time.time()
        
        # Verify the user's signature
        verify = verify_signature(clientDictInformation[listofClientAddress[i]][1], clientDictInformation[listofClientAddress[i]][2].encode('utf-8'), clientDict[listofClientAddress[i]])
     
        end1 = time.time()
        
        if (str(verify) == "True"):
            userlist.append(listofClientAddress[i])

        verifyTime = end1 - start1
        userVerifyTime.append(verifyTime)

    return sum(userVerifyTime)

def handle_User(conn, address, clientDict, public_key_sign, commitmentUse):
    """
    Handle communication and data exchange with a user.
    Algorithm 1 - Setup (Phase 1) - Step 7
    """
    send_data = "OK@."
    conn.send(send_data.encode(FORMAT))
    # Receive User's public_key_sign.
    clientPublicKeySign = conn.recv(SIZE) 
    # Send public_key_sign to Users. 
    clientDict[address[1]] = clientPublicKeySign
    conn.send(public_key_sign.format()) # Algorithm 1 - Setup (Phase 1) - Step 7      

    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        cmd = data.split("@")    
        if cmd[0] == "train":
            finalMaskedWeightList =[]
           
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 

            # Receive the masked weight list from the user
            rfile = conn.makefile('rb')
            header = rfile.read(4)
            datalen, = struct.unpack('!L', header)
            data_bytes = rfile.read(datalen*32+datalen-1)
            finalMaskedWeightList = data_bytes.decode('utf-8').split(',')
            
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 
            
            # If commitment is used, receive and store the commitment
            if commitmentUse == 1:
                commitment = conn.recv(SIZE)
                cm1 = struct.unpack(f"!{len(commitment)}s", commitment)
                commitment_x = cm1[0].decode('utf-8')

                send_data1 = "OK@"
                conn.send(send_data1.encode(FORMAT)) 

                commitment2 = conn.recv(SIZE)
                cm2 = struct.unpack(f"!{len(commitment2)}s", commitment2)
                commitment_Y = cm2[0].decode()

                cmDict[address[1]] = int(commitment_x), int(commitment_Y)
                send_data = "OK@"
                conn.send(send_data.encode(FORMAT)) 
            else:
                cm = Point(None, None, None)
                commitment_x = str(cm.x())
                commitment_Y = str(cm.y())

            # Receive the user's signature
            sigForMaskingUpdates = conn.recv(SIZE)
            send_data = "OK@Server: Message M and Sig received."
            conn.send(send_data.encode(FORMAT)) 

            strForSig = str(finalMaskedWeightList) + commitment_x + commitment_Y
            mystr = strForSig.encode('utf-8')
            messageMForSigHash = hashlib.sha256(mystr).hexdigest()

            # Store the received data
            listOfyInclient.append(finalMaskedWeightList)
            listofClientAddress.append(address[1])
            clientDictInformation[address[1]] = finalMaskedWeightList, sigForMaskingUpdates, messageMForSigHash
            break
        else:
            continue

def handle_AN(conn, address, assistantNodeDict):
    """
    Handle communication and data exchange with an assistant node.
    """
    send_data = "OK@."
    conn.send(send_data.encode(FORMAT))
    assistantNodePublicKeySign = conn.recv(SIZE) # Receive AN's public_key_sign.   
    assistantNodeDict[address[1]] = assistantNodePublicKeySign

    while True:
        data = conn.recv(SIZE).decode(FORMAT)
        cmd = data.split("@")
    
        if cmd[0] == "checkdelta":
            a_from_AN = []
            
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 

            # Receive the masked updates from the assistant node        
            rfile = conn.makefile('rb')
            header = rfile.read(4)
            datalen, = struct.unpack('!L', header)
            data_bytes = rfile.read(datalen*32+datalen-1)
            a_from_AN = data_bytes.decode('utf-8').split(',')
            
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 
            messageMdoubleP_I_L = conn.recv(SIZE)
            send_data = "OK@"
            conn.send(send_data.encode(FORMAT)) 

            sigForMDoublePrimeFromAssistantNode = conn.recv(SIZE)

            # Store the received data
            AssistantNodelist.append(address[1])
            AssistantNodeDictInformation[address[1]] = a_from_AN, messageMdoubleP_I_L, sigForMDoublePrimeFromAssistantNode
            break
        else:
            continue

def manageConnections(public_key_sign, clientDict, assistantNodeDict, NumberOfUsers, NumberOfANs, commitmentUse):
    """
    Manage incoming connections from clients and assistant nodes.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(4096)
    
    total_connections = NumberOfUsers+NumberOfANs
    user_threads = []
    assisting_node_threads = []
    connections_accepted = 0
    last_connection = None

    # Accept connections from clients and assistant nodes
    while connections_accepted < total_connections:
        conn, address = server.accept()
        conn.send("OK@".encode(FORMAT))            
        ClientORAssistantNode = conn.recv(SIZE).decode('latin1')

        if ClientORAssistantNode == "1": #Client       
            user_thread = threading.Thread(target=handle_User, args=(conn, address, clientDict, public_key_sign,commitmentUse,))  
            user_thread.start()
            user_threads.append(user_thread)
            last_connection = conn

        elif ClientORAssistantNode == "2": #AssistantNode  
            assisting_node_thread = threading.Thread(target=handle_AN, args=(conn, address, assistantNodeDict,))
            assisting_node_thread.start()
            assisting_node_threads.append(assisting_node_thread)

        connections_accepted += 1

    # Wait for all threads to finish
    for user_thread in user_threads:
        user_thread.join()
    for assisting_node_thread in assisting_node_threads:
        assisting_node_thread.join()

    return server, last_connection

def KeyGen():
    """
    Generate a key pair.
    Algorithm 1 - Setup (Phase 1) - Step 7
    """
    start_setup_phase = time.time()
    private_key_sign = PrivateKey()
    public_key_sign = private_key_sign.public_key
    end_setup_phase = time.time()
    keyGenTime = end_setup_phase-start_setup_phase

    return public_key_sign, private_key_sign, keyGenTime

def main():
    """
    Main function to initialize the server, handle connections, and perform secure aggregation.
    """
    # Parse command-line arguments
    NumberOfUsers = int(sys.argv[1])
    NumberOfANs = int(sys.argv[2])
    commitmentUse = int(sys.argv[3]) # 0 = without commiment & 1 = with commitment
    printAggOutput = int(sys.argv[4])
    bandwidthPrint = int(sys.argv[5])

    print("Server: Server is up")
    print("Server: Num of Users", NumberOfUsers)
    print("Server: Num of Assisting Nodes", NumberOfANs)

    # Generate the key
    public_key_sign, private_key_sign, keyGenTime = KeyGen()
    print("Server: Setup phase finished.")
    public_key_bytes = public_key_sign.format(compressed=True)
    outboundBandWidth.append(len(public_key_bytes) * NumberOfUsers)

    # Manage incoming connections
    serverSocket, last_connection = manageConnections(public_key_sign, clientDict, assistantNodeDict, NumberOfUsers, NumberOfANs, commitmentUse)

    print("Server: Awaiting all clients...")
    ver_user_time = verifySigofUsers()
    ver_AN_time = verifySigofANs()
    aggTime1, aggTime2, aggTime3, flag = checkUserListCondition(printAggOutput, NumberOfUsers, private_key_sign)

    # If all users are verified, perform the aggregation and send results
    if flag == 0:
        if commitmentUse == 1:
            computeX() # Algorithm 2 - Aggregation (Phase 2) - Step 5
            send_x_w(last_connection)
        if bandwidthPrint == 0:
            printResults(aggTime1, aggTime2, aggTime3, keyGenTime, ver_user_time, ver_AN_time, commitmentUse)
            print("")
        elif bandwidthPrint == 1:
            printResults(aggTime1, aggTime2, aggTime3, keyGenTime, ver_user_time, ver_AN_time, commitmentUse)
            print("")
            printOutboundBandwidth()
        else:
            # Print only the outbound bandwidth
            print("")
            printOutboundBandwidth()

    serverSocket.close()

if __name__ == "__main__":
    main()
