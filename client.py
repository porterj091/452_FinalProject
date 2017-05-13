'''
    Author: Joseph Porter, Luis, Hayley, kevin
    Description: Client side code for a secure chat application
'''
import websocket
import Crypto
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
import sys
import thread
import time


ws = websocket.create_connection('ws://localhost:3000')
userid = ''
password = ''
quitting = False
inSession = False

AES_SessionKey = ''

def login():
    ''' prompt the user for authentication '''
    global userid
    global password
    print('\nLogin to the Secure Chat Application!!\n')
    userid = raw_input('Username: ')
    password = raw_input('Password: ')

def padAESMessage(m):
    ''' Pad the message with ^ as its added input for AES messages '''
    # This is the message padding in 16 byte lengths
    while(len(m) % 16 != 0):
        m += "^"

def encryptAES(plaintext):
    ''' Encrypt the plaintext with a AES session key '''

def decryptAES(ciphertext):
    ''' Decrypt the ciphertext with a AES session key '''

def encryptServerRSAPublic(plaintext):
    ''' Will encrypt the plaintext with the public key of the server '''
    # Get the keys for the server
    (public_key, private_key) = getKeyPair('./keys/server_public.pem', './keys/server_private.pem')

    server_public_key_object = RSA.importKey(public_key)

    # Create the ciphertext
    cipher = PKCS1_OAEP.new(server_public_key_object)
    ciphertext = cipher.encrypt(json.dumps(plaintext))
    return ciphertext


def authenticationProtocol():
    ''' Protocol used to init the connection between the server and the client '''
    global userid, password, ws

    # Get the hash digest from the password
    password = hashlib.sha256(password).hexdigest()
    rnd = Random.new().read(5)

    message = { 'userid': userid, 'password': password, 'nonce': rnd.encode('base64')}

    ciphertext = encryptServerRSAPublic(message)

    # Message with header and encrypted data
    encrypted_message = { 'type': 'auth', 'message': ciphertext.encode('base64')}


    # Send the server rsa encrypted message init the message
    ws.send(json.dumps(encrypted_message))


    returnMessage = ws.recv()

    try:
        statusMessage = json.loads(decryptClientRSA(returnMessage))

        if statusMessage['nonce'] == message['nonce'] + 'aa':
            print('##### Sucessful Login #####')
        else:
            print('===== Nonce does not compute =====')
            sys.exit(1)
    except:
        print(returnMessage)
        sys.exit(1)


def decryptClientRSA(ciphertext):
    ''' Use the clients private key to decrypt the ciphertext '''
    global userid, password
    publicFilename = './keys/' + userid + '_public.pem'
    privateFilename = './keys/' + userid + '_private.pem'

    # Get the keys for the client
    try:
        (public_key, private_key) = getKeyPair(publicFilename, privateFilename)
    except:
        print('Could not find RSA key for that user')
        sys.exit(1)

    clients_public_key_object = RSA.importKey(public_key)
    clients_private_key_object = RSA.importKey(private_key)
    clientCipher = PKCS1_OAEP.new(clients_private_key_object)
    return clientCipher.decrypt(ciphertext.decode('base64'))


def showCommands():
    ''' Will show commands to the user before input is taken'''
    print('\nCommands that can be used:\n')
    print('Commands must be in front of text input!!!')
    print('\t$$showOnline: Will show users that are currently online')
    print('\t$$invite [users]: invite users to join your chat session')
    print('\t$$quit: Exit the chat session and quit program\n')




def getKeyPair(keyfile_public, keyfile_private):
    ''' Will return a private and public key tuple '''
    public_key = ''
    private_key = ''
    with open(keyfile_public, 'r') as _file:
        public_key = _file.read()
    with open(keyfile_private, 'r') as _file:
        private_key = _file.read()

    return (public_key, private_key)


def sendMessages(*args):
    ''' Will handle the user input for messages '''
    global quitting, inSession, userid, ws
    while(True and quitting == False):
        message = raw_input('Message: ')

        s_message = message.split(' ')

        if s_message[0] == '$$quit':
            print ('===== Quiting the chat session =====')
            quitting = True
            message = { 'controlType': 'quit', 'userid': userid }
            ciphertext = encryptServerRSAPublic(message).encode('base64')
            ws.send(json.dumps({'type': 'control', 'message': ciphertext}))
        elif s_message[0] == '$$invite':
            print ('Inviting users to chat')

        elif s_message[0] == '$$showOnline':
            message = { 'controlType': 'showOnline', 'userid': userid }
            ciphertext = encryptServerRSAPublic(message).encode('base64')
            ws.send(json.dumps({'type': 'control', 'message': ciphertext}));
        elif inSession is True:
            ws.send(json.dumps({'type': 'message', 'message': message}))
        else:
            print ('\n#### Not in a Chat Session either wait to be invited or invite others ####\n')
        time.sleep(0.3)
    '''else:
        thread.exit()'''

def recvMessages(*args):
    ''' Will be listening for messages '''
    global quitting, inSession, ws
    while(True and quitting == False):
        try:
            message = json.loads(ws.recv())

            # All control messages will be using RSA encryption
            if message['type'] == 'control':
                server_Message = json.loads(decryptClientRSA(message['message']))
                if server_Message['controlType'] == 'showOnline':
                    printVal = '\n#### Users Online:'
                    for name in server_Message['users']:
                        printVal += ' ' + name
                    printVal += ' ####\n'
                    print printVal
            elif message['type'] == 'message':  # Normal messages uses AES session key
                print 'message'
            else:
                print ('===== Dont understand that message type =====')
        except:
            print ('JSON loading failure')
    '''else:
        thread.exit()'''

def messageService():
    ''' Messaging application after user has invited the users needed '''
    global ws

    # Start threads to handle input and output
    thread.start_new_thread(sendMessages, ())
    thread.start_new_thread(recvMessages, ())

    # Stall the main thread from doing anything
    while(True and quitting == False):
        pass
    else:
        time.sleep(1)
        ws.close()
        sys.exit(0)



aesObj = AES.new('passwordpassword', AES.MODE_ECB)
if __name__ == '__main__':
    login()
    authenticationProtocol()
    showCommands()
    messageService()
    ws.close()
