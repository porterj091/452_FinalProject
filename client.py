import websocket
from Crypto.Cipher import AES

aesObj = AES.new('passwordpassword', AES.MODE_ECB)
if __name__ == '__main__':
    ws = websocket.create_connection('ws://localhost:3000')
    print ('Sending this message: I am Joseph and this is avery long message that needs to be decrypted')
    message = 'I am Joseph and this is avery long message that needs to be decrypted'

    #Pad the message with ^
    while(len(message) % 16 != 0):
        message += "^"
    ws.send(message)

    # get result from server
    result = ws.recv()
    print ('Encrypted Message from server: %s' %(result))
    decrypted = aesObj.decrypt(result.decode('base64'))

    # remove the padding
    recvMessage = ''
    found = False
    for i in range(len(decrypted)):
        if found is True:
            pass
        elif decrypted[i] is '^':
            decrypted = decrypted[:i]
            i = len(decrypted) + 1
            found = True


    print ('Decrypted Message from server: %s' %(decrypted))
    ws.close()
