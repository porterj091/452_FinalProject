import websocket


if __name__ == '__main__':
    ws = websocket.create_connection('ws://localhost:3000')
    print ('Sending this message: I am Joseph')
    ws.send('I am Joseph')
    result = ws.recv()
    print 'Message from server: %s' %(result)
    ws.close()
