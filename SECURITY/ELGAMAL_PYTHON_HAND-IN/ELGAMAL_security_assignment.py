# Lamberto Ragnolini 
# Security 1 course
# mandatory hand-in 1

import random

class ELGAMAL:

    def __init__(self,p,g,PK):
        self.p = p
        self.g = g
        self.PK = PK # g^x mod p but we do't know x because it's the private of Bob, we know directly PK

# EX1

# text:

# You are Alice and want to send 2000 kr. to Bob through a confidential
# message. You decide to use the ElGamal public key method.
# The keying material you should use to send the message to Bob is as
# follows:
# • The shared base g=666
# • The shared prime p=6661
# • Bob’s public key PK = g^x mod p =2227
# Send the message ’2000’ to Bob.

# code : 

    # this function encrypts c1
    def compute_c1(self,r):
        return (self.g**r) % self.p 

    # this function encrypts c2
    def compute_c2(self,M,r):  
        return (M*(self.PK**r)) % self.p # PK^k is the mask that later Bob will be able to remove with his x

    # this function is used to encrypt the message and send it
    def send(self,message):
        r = random.randint(1, self.p-1) #Alices secret key that is chose at random every time, remember it should be smaller than our p
        c1 = self.compute_c1(r) 
        c2 = self.compute_c2(message,r)
        cypher_pair = (c1,c2) #both numbers must be in the range 0...p-1
        print(f"this is the encrypted sent pair : {cypher_pair}")
        return cypher_pair

# EX2 :

# text:

# You are now Eve and intercept Alice’s encrypted message. Find Bob’s
# private key and reconstruct Alice’s message.

# code:

    # this auxilliary function is used to decyrpt the message that Alice sended to Bob
    def decryption(self,c1,c2,x):
        hide_msg = (c1**x) % self.p  # this means doin -> (g^r)^x mod p
        # To remove the hiding now we have to :
            # compute modular inverse of hide msg
            # compute mod p of the modular inverse
        decryption = (pow(hide_msg,-1,self.p) * c2 ) % self.p  
        return decryption

    # This function is used to intercept the message that ALice sended and find Bob's private key
    # returns the decrypted message
    def interceptance(self,cypher_pair):
        # explode the pair
        c1 = cypher_pair[0]
        c2 = cypher_pair[1]
        # now we need to find x of Bob knowing p,g,PK
        # we know PK = g^x mod p
        # what we wanna do is find that x that given as exponent to g gives 2227 when we apply mod p
        # This method uses a brute force approach
        x = 0
        for i in range(self.p):
            if ((self.g**i) % self.p) == self.PK:
                x = i
                print(f"Bobs secret key is {x}")
                break
        
        dec = self.decryption(c1,c2,x)
        print(f"the decrypted message is {dec}")
        return dec


# EX3 :

# text :

# You are now Mallory and intercept Alice’s encrypted message. However,
# you run on a constrained device and are unable to find Bob’s private key.
# Modify Alice’s encrypted message so that when Bob decrypts it, he will
# get the message ’6000’.

# code :

    # This function is used to intercept the message Alice sent to Bob and change it's content
    def Mallory_intercept(self,cypher_pair, new_message):
        # explode the pair
        c1 = cypher_pair[0]
        new_c2 = cypher_pair[1] *new_message 
        new_cypher_pair = (c1,new_c2)
        print(f"the new encrypted message is {new_cypher_pair}")
        return new_cypher_pair



# initializations and function calls

# this are the parameters you can use for your ELGAMAL encryption
# change this for different outcomes
p = 6661
g = 666
PK = 2227

# payloads
Alice_msg = 2000
# ASSUMING THAT THE RECEIVED VALUE IS ALREADY 2000
Mallory_msg = 3

# instance of the class
E = ELGAMAL(p,g,PK)

# function calls for the exercises

# ex1
pair = E.send(Alice_msg)

# ex2
E.interceptance(pair)

# ex3
Mallory_encrypted_msg = E.Mallory_intercept(pair, Mallory_msg)
# this function call is done to show that when Bob will decrypt he will see Mallory payload (the changed message)
E.interceptance(Mallory_encrypted_msg)
        

