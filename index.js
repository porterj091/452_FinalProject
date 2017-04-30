var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;

var port = 3000;

var ws = new WebSocketServer({
    port: port
});


var clients = [];

console.log('#### Server Started ####');
ws.on('connection', function(socket) {
    console.log('client connection established');


    socket.on('message', function(data) {
        socket.send('Echo message recieved: ' + data);
    });
});
