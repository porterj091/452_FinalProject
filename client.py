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


def authenticationProtocol():
    ''' Protocol used to init the connection between the server and the client '''
    global userid, password, ws

    # Get the hash digest from the password
    password = hashlib.sha256(password).hexdigest()
    rnd = Random.new().read(5)

    message = { 'userid': userid, 'password': password, 'nonce': rnd.encode('base64')}

    # Get the keys for the client
    (public_key, private_key) = getKeyPair('./keys/clients_public.pem', './keys/clients_private.pem')

    clients_public_key_object = RSA.importKey(public_key)
    clients_private_key_object = RSA.importKey(private_key)

    # Get the keys for the server
    (public_key, private_key) = getKeyPair('./keys/server_public.pem', './keys/server_private.pem')

    server_public_key_object = RSA.importKey(public_key)

    # Create the ciphertext
    cipher = PKCS1_OAEP.new(server_public_key_object)
    ciphertext = cipher.encrypt(json.dumps(message))

    # Message with header and encrypted data
    encrypted_message = { 'type': 'auth', 'message': ciphertext.encode('base64')}


    # Send the server rsa encrypted message init the message
    ws.send(json.dumps(encrypted_message))

    clientCipher = PKCS1_OAEP.new(clients_private_key_object)

    statusMessage = json.loads(clientCipher.decrypt(ws.recv().decode('base64')))

    if statusMessage['status'] == 'bad':
        print('========== Incorrect Login ===========')
        sys.exit(1)
    elif statusMessage['nonce'] == message['nonce'] + 'aa':
        print('##### Sucessful Login #####')
    else:
        print('=========== Authentication Protocol not followed ============')
        sys.exit(1)


def showCommands():
    ''' Will show commands to the user before input is taken'''
    print('\nCommands that can be used:\n')
    print('Commands must be in front of text input!!!')
    print('\t$$showOnline: Will show users that are currently online')
    print('\t$$invite [users]: invite users to join your chat session')
    print('\t$$quit: Exit the chat session')




def getKeyPair(keyfile_public, keyfile_private):
    ''' Will return a private and public key tuple '''
    public_key = ''
    private_key = ''
    with open(keyfile_public, 'r') as _file:
        public_key = _file.read()
    with open(keyfile_private, 'r') as _file:
        private_key = _file.read()

    return (public_key, private_key)


def on_message(ws, message):
    print('\t\t\t\t\t' +  message)

def on_error(ws, error):
    print error
    sys.exit(1)

def on_close(ws):
    print '### Closing Down ###'

def on_open(ws):
    def run(*args):
        while(True and quitting == False):
            message = raw_input('Message: ')
            ws.send(message)
            time.sleep(0.3)

    thread.start_new_thread(run, ())

def sendMessages(*args):
    global quitting
    while(True and quitting == False):
        message = raw_input('Message: ')

        s_message = message.split(' ')

        if s_message[0] == '$$quit':
            print ('Quiting the chat session')
            quitting = True

        ws.send(json.dumps({'type': 'message', 'message': message}))
        time.sleep(0.3)
    else:
        ws.close()
        sys.exit(0)

def recvMessages(*args):
    global quitting
    while(True and quitting == False):
        message = ws.recv()
        print(message)
    else:
        ws.close()
        sys.exit(0)

def messageService():
    global ws

    # Start threads to handle input and output
    thread.start_new_thread(sendMessages, ())
    thread.start_new_thread(recvMessages, ())

    # Stall the main thread from doing anything
    while(True and quitting == False):
        pass



aesObj = AES.new('passwordpassword', AES.MODE_ECB)
if __name__ == '__main__':
    login()
    authenticationProtocol()
    showCommands()
    messageService()
    ws.close()
