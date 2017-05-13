'''
    Author: Joseph Porter, Luis, Hayley, kevin
    Description: Client side code for a secure chat application
'''
import websocket
import Crypto
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json

ws = websocket.create_connection('ws://localhost:3000')
userid = ''
password = ''

def login():
    ''' prompt the user for authentication '''
    global userid
    global password
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

    message = { 'userid': userid, 'password': password }

    (public_key, private_key) = getKeyPair('./keys/clients_public.pem', './keys/clients_private.pem')

    clients_public_key_object = RSA.importKey(public_key)
    clients_private_key_object = RSA.importKey(private_key)

    (public_key, private_key) = getKeyPair('./keys/server_public.pem', './keys/server_private.pem')

    server_public_key_object = RSA.importKey(public_key)

    ciphertext = server_public_key_object.encrypt(json.dumps(message), None)

    encrypted_message = { 'type': 'auth', 'message': ciphertext[0].encode('base64')}


    # Send the server rsa encrypted message init the message
    ws.send(json.dumps(encrypted_message))




def getKeyPair(keyfile_public, keyfile_private):
    ''' Will return a private and public key tuple '''
    public_key = ''
    private_key = ''
    with open(keyfile_public, 'r') as _file:
        public_key = _file.read()
    with open(keyfile_private, 'r') as _file:
        private_key = _file.read()

    return (public_key, private_key)



aesObj = AES.new('passwordpassword', AES.MODE_ECB)
if __name__ == '__main__':
    login()
    authenticationProtocol()
    ws.close()
