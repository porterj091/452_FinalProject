var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;

var crypto = require('crypto');
var NodeRSA = require('node-rsa');
var fs = require('fs');

var server_public_key = new NodeRSA();
var server_private_key = new NodeRSA();


fs.readFile('./keys/server_public.pem', 'utf8', function(err, data) {
    if (err) throw err;
    console.log(data);
    server_public_key.importKey(data, 'public');
});

fs.readFile('./keys/server_private.pem', 'utf8', function(err, data) {
    if (err) throw err;
    console.log(data);
    server_private_key.importKey(data, 'private');
});



var port = 3000;

var ws = new WebSocketServer({
    port: port
});

var registeredUsers = [{
        // password: password
        username: 'joseph',
        password: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
    },
    { // password: password1
        username: 'luis',
        password: '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e'
    },
    { // password: password2
        username: 'hayley',
        password: '6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4'
    },
    { // password: password3
        username: 'kevin',
        password: '5906ac361a137e2d286465cd6588ebb5ac3f5ae955001100bc41577c3d751764'
    }
];


var clients = [];

console.log('#### Server Started ####');
ws.on('connection', function(socket) {
    console.log('client connection established');


    socket.on('message', function(data) {
        msg = JSON.parse(data);

        if (msg.type === 'auth') {

        }
        /*if (data) {
            var encrypted = encryptAES('passwordpassword', data);
            console.log('Original message: ' + data);
            console.log('Encrypted message in base64: ' + encrypted);
            socket.send(encrypted);
        }*/
    });
});


// Need to recreate the cipher each time you want to encrypted or decrypt something
function encryptAES(sessionKey, data) {
    var encipher = crypto.createCipheriv('aes-128-ecb', sessionKey, '');
    var encryptdata = encipher.update(data, 'utf8', 'base64');

    encryptdata += encipher.final('base64');
    //encode_encryptdata = new Buffer(encryptdata, 'binary').toString('base64');
    return encryptdata;
}

function decryptAES(sessionKey, data) {
    data = new Buffer(data, 'base64').toString('binary');

    var decipher = crypto.createDecipheriv('aes-128-ecb', sessionKey, '');
    var decoded = decipher.update(data, 'base64', 'utf8');

    decoded += decipher.final('utf8');
    return decoded;
}
