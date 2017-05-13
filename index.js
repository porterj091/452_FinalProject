var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;

var crypto = require('crypto');
var NodeRSA = require('node-rsa');
var fs = require('fs');

var server_public_key = new NodeRSA();
var server_private_key = new NodeRSA();


fs.readFile('./keys/server_public.pem', 'utf8', function(err, data) {
    if (err) throw err;
    //console.log(data);
    server_public_key.importKey(data, 'public');
});

fs.readFile('./keys/server_private.pem', 'utf8', function(err, data) {
    if (err) throw err;
    //console.log(data);
    server_private_key.importKey(data, 'private');
});

fs.readFile('./keys/server_private.pem', 'utf8', function(err, data) {
    if (err) throw err;
    //console.log(data);
    server_private_key.importKey(data, 'private');
});

var clients_key = getClients_PublicKey('clients');



var port = 3000;

var ws = new WebSocketServer({
    port: port
});

var registeredUsers = [{
        // password: password
        username: 'joseph',
        password: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        online: false
    },
    { // password: password1
        username: 'luis',
        password: '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e',
        online: false
    },
    { // password: password2
        username: 'hayley',
        password: '6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4',
        online: false
    },
    { // password: password3
        username: 'kevin',
        password: '5906ac361a137e2d286465cd6588ebb5ac3f5ae955001100bc41577c3d751764',
        online: false
    }
];

// Will hold all the messages sent
var messages = [];

console.log('#### Server Started ####');
ws.on('connection', function(socket) {
    console.log('client connection established');


    socket.on('message', function(data) {
        msg = JSON.parse(data);

        if (msg.type === 'auth') {
            var decryptedMessage = server_private_key.decrypt(msg.message, 'utf8');
            decryptedMessage = JSON.parse(decryptedMessage);

            var socketMessage;

            if (checkAuth(decryptedMessage)) { // User is allowed
                socketMessage = clients_key.encrypt(JSON.stringify({
                    status: 'ok',
                    nonce: nonceModify(decryptedMessage.nonce)
                }), 'base64');
                socket.send(socketMessage);
            } else {
                socketMessage = clients_key.encrypt(JSON.stringify({
                    status: 'bad',
                    nonce: nonceModify(decryptedMessage.nonce)
                }), 'base64');

                socket.send(socketMessage);
            }


        } else if (msg.type === 'message') {
            socket.send(msg.message);
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

function checkAuth(attempt) {
    var authenticated = false;
    // Make sure that the messages contains the correct fields
    if (!attempt.userid && !attempt.password) {
        return authenticated;
    }

    // Find if the username and password are within the registeredUsers
    registeredUsers.forEach(function(user) {
        if ((user.username === attempt.userid) && (user.password === attempt.password) && !user.online) {
            user.online = true;
            authenticated = true;
        }
    });

    return authenticated;
}

function nonceModify(nonce) {
    return nonce + 'aa';
}

function getClients_PublicKey(client) {
    var keyName = './keys/' + client + '_public.pem';
    var key = new NodeRSA();
    fs.readFile(keyName, 'utf8', function(err, data) {
        if (err) throw err;
        key.importKey(data, 'public');
    });

    return key;
}
