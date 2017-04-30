var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;

var crypto = require('crypto');

var port = 3000;

var ws = new WebSocketServer({
    port: port
});


var clients = [];

console.log('#### Server Started ####');
ws.on('connection', function(socket) {
    console.log('client connection established');


    socket.on('message', function(data) {
        if (data) {
            var cipher = makeAESCipher('passwordpassword', 'E');
            var encrypted = cipher.update(data, 'utf8');
            encrypted += cipher.final('base64');
            console.log('Original message: ' + data);
            console.log('Encrypted message in base64: ' + encrypted);
            socket.send(encrypted);
        }
    });
});


// Need to recreate the cipher each time you want to encrypted or decrypt something
function makeAESCipher(sessionKey, mode) {

    // For some reason need an iv although ECB doesn't use it
    if (mode === 'E') {
        return crypto.createCipheriv('AES-128-ECB', sessionKey, '');
    } else if (mode === 'D') {
        return crypto.createDecipheriv('AES-128-ECB', sessionKey, '');
    } else {
        throw new Error('Mode must be [E|D]');
    }
}
