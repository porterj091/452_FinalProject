import websocket
from Crypto.Cipher import AES

aesObj = AES.new('passwordpassword', AES.MODE_ECB)
if __name__ == '__main__':
    ws = websocket.create_connection('ws://localhost:3000')
    print ('Sending this message: I am Joseph')
    ws.send('I am Joseph')
    result = ws.recv()
    print ('Encrypted Message from server: %s' %(result))
    decrypted = aesObj.decrypt(result.decode('base64'))
    print ('Decrypted Message from server: %s' %(decrypted))
    ws.close()
