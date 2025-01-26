
import socket
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# //////////////////////////////////////////////////////////////////
# READ REPORT/README TO KNOW HOW TO RUN THE WHOLE ASSIGNMENT
# //////////////////////////////////////////////////////////////////


# global variables that will be used all over the functions

# handle server conditions for sending and receiveing informations
total_sum = 0
num_patients = 0 
connections = 0

# port numbers of the clients
Alice = 8442
Bob = 8441
Charlie = 8440

# Public keys that will be received by other parties in the exchange 
Alice_pk = ""
Bob_pk = ""
Charlie_pk = ""


# Hospital Public key loaded from the key file
with open("../KEYS/server_public_key.pem", "rb") as f:
    hospital_public_key = serialization.load_pem_public_key(f.read())
# Hospital private key loaded from the key file
with open("../KEYS/server_private_key.pem", "rb") as f:
    hospital_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# This function is the functon that will distribute the Hospital public key
# to whoever needs it, in our  case to the clients Alice,Bob and Charlie
def distribute_key(pk,who) :

    print(f"sending pk to {who}")

    # Create a secure SSL context
    # This loads the certificates which will be asked from the other parties to prove that the Hospital is safe
    context = ssl.create_default_context()
    context.load_cert_chain(certfile="../CERTS/Hospital.crt", keyfile="../CERTS/Hospital.key")
    context.load_verify_locations("../CERTS/myCA.pem")
    context.verify_mode = ssl.CERT_REQUIRED 

    # conncets to who needs to send the pk 
    secure_sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='localhost')
    secure_sock.connect(('localhost', who))

    try:
        # Serialize the Hospital public key to PEM format
        pem = hospital_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Given that our keys are already in a pem format in the files where we saved them 
        # there is no need to serialize them we can just send it
        secure_sock.sendall(pem) 
        print(f"My public key has just been sent to : {who}")
    finally:
        # close connection after every exchange
        secure_sock.close()


# Create a secure SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="../CERTS/Hospital.crt", keyfile="../CERTS/Hospital.key")
context.load_verify_locations("../CERTS/myCA.pem")
context.verify_mode = ssl.CERT_REQUIRED


# Main process function, this is the function that opens the Hospital's channel, here is where connection will pass througha and
# where the Hospital will be able to transfer informations 
def start_Hospital_Server():
    global total_sum
    global num_patients  
    global connections
    global Alice_pk
    global Bob_pk
    global Charlie_pk
    global Alice
    global Bob
    global Charlie

    # siomple Creation of a secure TCP/IP socket initialization
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(sock, server_side=True)
    secure_sock.bind(('localhost', 8443))
    # the number is in the listen is the max num of queued connection it can have,
    # we don't really care much about it so lets place 3 parties + hospital + 1 safe one 
    secure_sock.listen(5)

    print("Server listening on port 8443...")

    while True:
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
                decrypted_data = hospital_private_key.decrypt(
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
        else :

            # This is the condition that handles the pk's reception
            # use the Organiation Name to identify who's pk is it from the certificate and save it
           
        #  REMEMBER THAT NOW WE ARE STORING BASE64 STRINGS, THEY WILL NEED TO BE CONVERTED INTO OBJECTS LATER,
        #  Te hospital will though not need to use them so we will never convert them...

            # the following is an example of what getpeercert() returns 
            # this is the cert that we receive {'subject': ((('countryName', 'dk'),), (('stateOrProvinceName', 'cop'),), (('localityName', 'cop'),), (('organizationName', 'cop'),), (('organizationalUnitName', 'cop'),), (('commonName', 'localhost'),), (('emailAddress', 'Bob@gmail.com'),)), 'issuer': ((('countryName', 'dk'),), (('stateOrProvinceName', 'cop'),), (('localityName', 'cop'),), (('emailAddress', 'myCA@gmail.com'),)), 'version': 1, 'serialNumber': '6A87FF44E0D1BE0FDD86F19A7D083E133530B343', 'notBefore': 'Oct 16 13:37:10 2024 GMT', 'notAfter': 'Feb 28 13:37:10 2026 GMT'}
           
            print("processing certificate from : ", client_cert['subject'][6][0][1])

            #  WILL LEAVE THE PRINT COMMENTED if you wanna see the incoming pk just uncomment them

            if client_cert['subject'][6][0][1] == 'Alice@gmail.com' :
                Alice_pk = connection.recv(1024)
                # print("ALice -> ", Alice_pk)
            elif client_cert['subject'][6][0][1] == 'Bob@gmail.com' :
                Bob_pk = connection.recv(1024)
                # print("B ->",Bob_pk)
            elif client_cert['subject'][6][0][1] == 'Charlie@gmail.com' :
                Charlie_pk = connection.recv(1024)
                # print("C -> ", Charlie_pk)
            
            # remember to flag every timne a new pk came through and close the connection
            connections += 1
            connection.close()

            # check that all the keys are arrived so that we the Hospital can distribute its public key
            if connections >= 3:

                # due to complex packing and unpacking of the sent data 
                # I prefer to use more function calls and send a key at a time

                # distribute Hospital key to clients
                distribute_key(hospital_public_key,Alice)
                distribute_key(hospital_public_key,Bob)
                distribute_key(hospital_public_key,Charlie)

            
        # if all the clients have sent their data and the aggregated value has been computed locally,
        # this means that the hospital received all the data it needed.
        if total_sum > 0 and num_patients == 3: 
            print(f"Final aggregated value: {total_sum}")
            # The hospital received what was needed so can shut down the server
            break 

# start server
start_Hospital_Server()