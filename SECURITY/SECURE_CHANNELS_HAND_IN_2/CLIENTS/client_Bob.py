import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import random
import threading

# //////////////////////////////////////////////////////////////////
# READ REPORT/README TO KNOW HOW TO RUN THE WHOLE ASSIGNMENT
# //////////////////////////////////////////////////////////////////

# global variables that will be used all over the functions

# MOST IMPORTANT VARIABLE, THE LOCAL INITIAL VALUE OF THE PATIENT
# integers value in a range [0,...,R]
patient_value = 350


# handle server conditions for sending and receiveing informations
total_sum = 0
num_patients = 0  
connections = 0

# port numbers of the other clients and the hospital
Alice = 8442
Charlie = 8440
Hospital = 8443

# Public keys that will be received by other parties in the exchange 
Alice_pk = ""
Charlie_pk = ""
Hospital_pk = ""

# done variable to prevent server to send more than one time the splitted values
done = False

# Bob Public key loaded from the key file
with open("../KEYS/Bob_public.pem", "rb") as f:
    bob_public_key = serialization.load_pem_public_key(f.read())
# Bob private key loaded from the key file
with open("../KEYS/Bob_private.key", "rb") as f:
    bob_private_key = serialization.load_pem_private_key(f.read(), password=b'Boob')

# This function is the function that splits Bob's number into three giving him the ability of
# sending the other 2 clients their part to compute locally the aggregation and keep one for him to compute his aggregation
def three_split(input):
    # - 3 to prevent choosing the upper bound immediately
    # in this way the other two number will not be both 0
    safeExceed = 3
    input = input - safeExceed
    first = random.randint(1,input)
    # give randomness also to second draw if the new upper bound was chosen
    if (input-first == 0) :
        second = random.randint(1,safeExceed)
        safeExceed -= second
    else :
        # if new upper bound was not chosen pick randomly normally between what is remaining
        newInput = input-first
        second = random.randint(1,newInput)

    # now the remaining...
    third = (input - (first + second)) + safeExceed

    print(f"the split generated the following ->  {first} {second} {third} which adds up to the input : {third+first+second}")
    return first,second,third

# This function is the function to exchange Charlie's public key so that the other parties can
# communicate with Charlie using asymmetric encryption on the subsequent connections
def send_pk(pk, who) :

    print(f"sending pk to {who}")

    # Create a secure SSL context
    # This loads the certificates which will be asked from the other parties to prove that Bob is safe
    context = ssl.create_default_context()
    context.load_cert_chain(certfile="../CERTS/Bob.crt", keyfile="../CERTS/Bob.key")
    context.load_verify_locations("../CERTS/myCA.pem")
    context.verify_mode = ssl.CERT_REQUIRED

    # conncets to who needs to send the pk 
    secure_sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='localhost')
    secure_sock.connect(('localhost', who))

    try:
        # Serialize the public key to PEM format
        pem = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # send the pk 
        secure_sock.sendall(pem)
        print(f"My public key has just been sent to : {who}")
    finally:
        # close connection after every exchange
        secure_sock.close()



# This function is the one that sends the actual data meaning the aggregation value, both the splitted ones and 
# the locally computed aggregation 
def send_data(value, who, pk):

    print(f"the value I am sending before encryption is :  {value}")

    data = str(value).encode('utf-8')
    # when we receive the key and we store it into the global pk's it will be a string so we need to
    # ensure that the public key is in bytes and if not we convert it to bytes
    if isinstance(pk, str):
        pk = pk.encode('utf-8')

    # we need the key to be in pem format to encrypt the data
    pk = serialization.load_pem_public_key(pk)

    # Encription, as said in class USE LIBRARIESSS
    encrypted_data = pk.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Create a secure SSL context
    context = ssl.create_default_context()
    # present certificates that will be requested to prove safe identity
    context.load_cert_chain(certfile="../CERTS/Bob.crt", keyfile="../CERTS/Bob.key")
    context.load_verify_locations("../CERTS/myCA.pem")

    # conncets to who needs to send the encrypted data
    secure_sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='localhost')
    secure_sock.connect(('localhost', who))

    try:
        # send encrypted data
        secure_sock.sendall(encrypted_data)
        print(f"the encrypted value was sent to :  {who}")
    finally:
        # close connnection
        secure_sock.close()


# This function will handle the transfer of the data to the other clients,
# meaning it will send the proper splitted values to both Charlie and Alice
def handle_data_transfer(Bx2,Bx3) :

    global Charlie
    global Alice
    global Charlie_pk
    global Alice_pk

    # keys are global so we can access them directly
    send_data(Bx2, Charlie, Charlie_pk)
    send_data(Bx3,  Alice, Alice_pk)


# Create a secure SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="../CERTS/Bob.crt", keyfile="../CERTS/Bob.key")
context.load_verify_locations(cafile="../CERTS/myCA.pem")
context.verify_mode = ssl.CERT_REQUIRED 

# Main process function, this is the function that opens Bob's channel, here is where connection will pass througha and
# where Bob will be able to transfer informations 
def start_Bob_Server():
    global total_sum
    global num_patients  
    global connections
    global Alice_pk
    global Charlie_pk
    global Hospital_pk 
    global Alice
    global Charlie
    global Hospital
    global done
    global patient_value

    # siomple Creation of a secure TCP/IP socket initialization
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(sock, server_side=True)
    secure_sock.bind(('localhost', 8441))
    # the number is in the listen is the max num of queued connection it can have,
    # we don't really care much about it so lets place 3 parties + hospital + 1 safe one 
    secure_sock.listen(5)

    print("Server listening on port 8441...")

    # first thing first just for implementation design, every client will send their proper public key to the hospital 
    # and only when the hospital will have all of them, it will distribute his so 
    # first thing first send public key to hospital
    send_pk(bob_public_key,Hospital)

    # THE TIMER IS USED TO MAKE SURE ALL CLIENTS AND THE HOSPITAL HAVE A RUNNING SERVER BEFORE COMMUNICATING
    # MAKE SURE TO OPEN 4 TERMINAL WINDOWS 
    # FIRST RUN -> hospital 
    # then run -> ALICE, BOB, CHARLIE
    
    # then send the public key to Alice
    timer = threading.Timer(15, send_pk, args=(bob_public_key,Alice))
    timer.start()

    # then send the public key to Charlie
    timer = threading.Timer(20, send_pk, args=(bob_public_key,Charlie))
    timer.start()


    while True:
            
        # THis conditions check that we have all the pk's that we need and that we didn't already sent our splitted parts
        if connections >= 3 and done != True:

            # if that's the case, the following steps are computed :
            #   - split the patient value
            #   - delegate to auxilliary fuction the transfer of splitted values to other clients
            #   - make sure that our local aggregated sum starts with the splitted value we didn't send
            #   - set done var to true to flag the fact that values has been sent

            print("SENDING DATA FROOM BOB")

            Bx1,Bx2,Bx3 = three_split(patient_value)

            timer = threading.Timer(10, handle_data_transfer, args=(Bx2,Bx3))
            timer.start()

            total_sum += Bx1
            done = True


        # this listens to conncetions in case someone tries to connect with us
        connection, client_address = secure_sock.accept()

        # retrieve the connected party certificate used later
        client_cert = connection.getpeercert()

        # if we already have all the pk's then it means that we are receiveing data 
        # that must be decrypted otherwise what's been sent is a pk 
        if connections >= 3 :


            try:
                print(f"Connection from {client_address}")

                encrypted_data = connection.recv(1024)

                # Decrypt the data using our oreviously loaded private key
                decrypted_data = bob_private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # take into account right conversions
                value = decrypted_data.decode('utf-8')
                print(f"Received decrypted value: {value}")
                
                # REMEMBER we are expecting a number, an integer to be more speficic
                patient_value = int(decrypted_data)
                # add what was received to the aggregated value
                total_sum += patient_value
                # flag the fact that a a client sent data
                num_patients += 1

                # Print the current status of aggregation
                print(f"Total sum: {total_sum} from {num_patients} patients.")

            finally:
                # close connection
                connection.close()
                #  if aggregated value has been fully computed, send it to the hospital
                if total_sum > 0 and num_patients == 2:  
                    print(f"sending the current aggregated value: {total_sum} to the hospital",)
                    send_data(total_sum, Hospital, Hospital_pk)
                    done = True 
        
        else :

            # This is the condition that handles the pk's reception
            # use the Organiation Name to identify who's pk is it from the certificate and save it
           
        #  REMEMBER THAT NOW WE ARE STORING BASE64 STRINGS, THEY WILL NEED TO BE CONVERTED INTO OBJECTS LATER

            # the following is an example of what getpeercert() returns 
            # this is the cert that we receive {'subject': ((('countryName', 'dk'),), (('stateOrProvinceName', 'cop'),), (('localityName', 'cop'),), (('organizationName', 'cop'),), (('organizationalUnitName', 'cop'),), (('commonName', 'localhost'),), (('emailAddress', 'Bob@gmail.com'),)), 'issuer': ((('countryName', 'dk'),), (('stateOrProvinceName', 'cop'),), (('localityName', 'cop'),), (('emailAddress', 'myCA@gmail.com'),)), 'version': 1, 'serialNumber': '6A87FF44E0D1BE0FDD86F19A7D083E133530B343', 'notBefore': 'Oct 16 13:37:10 2024 GMT', 'notAfter': 'Feb 28 13:37:10 2026 GMT'}
    
            print("processing certificate from : ",client_cert['subject'][6][0][1])
            
            #  WILL LEAVE THE PRINT COMMENTED if you wanna see the incoming pk just uncomment them

            if client_cert['subject'][6][0][1] == 'Alice@gmail.com' :
                # print("ALice -> ", Alice_pk)
                Alice_pk = connection.recv(1024)
            elif client_cert['subject'][6][0][1] == 'Charlie@gmail.com' :
                Charlie_pk = connection.recv(1024)
                # print("Charlie -> ", Charlie_pk)
            else :
                Hospital_pk = connection.recv(1024)
                # print("Hospital -> ", Hospital_pk)
            
            # remember to flag every timne a new pk came through and close the connection
            connections += 1
            connection.close()

    
# start server 
start_Bob_Server()