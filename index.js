var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;

var crypto = require('crypto');
var NodeRSA = require('node-rsa');
var fs = require('fs');

var server_public_key = new NodeRSA();
var server_private_key = new NodeRSA();

var AES_SessionKey = '';


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


var port = 3000;

var ws = new WebSocketServer({
    port: port
});

var registeredUsers = [{
        // password: password
        username: 'joseph',
        password: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        online: false,
        public_key: getClients_PublicKey('joseph')
    },
    { // password: password1
        username: 'luis',
        password: '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e',
        online: false,
        public_key: getClients_PublicKey('luis')
    },
    { // password: password2
        username: 'hayley',
        password: '6cf615d5bcaac778352a8f1f3360d23f02f34ec182e259897fd6ce485d7870d4',
        online: false,
        public_key: getClients_PublicKey('hayley')
    },
    { // password: password3
        username: 'kevin',
        password: '5906ac361a137e2d286465cd6588ebb5ac3f5ae955001100bc41577c3d751764',
        online: false,
        public_key: getClients_PublicKey('kevin')
    }
];

// Will hold all the messages sent
var messages = [];

var clients_inSession = [];

console.log('#### Server Started ####');
ws.on('connection', function(socket) {
    console.log('client connection established');


    socket.on('message', function(data) {
        msg = JSON.parse(data);
        console.log(msg);

        if (msg.type === 'auth') {
            var decryptedMessage = server_private_key.decrypt(msg.message, 'utf8');
            decryptedMessage = JSON.parse(decryptedMessage);
            socket.userid = decryptedMessage.userid;

            socket.send(checkAuth(decryptedMessage))


        } else if (msg.type === 'message') {
            ws.clients.forEach(function(clientSocket) {
                clients_inSession.forEach(function(user) {
                    if (clientSocket.userid === user.username) {
                        clientSocket.send(JSON.stringify(msg));
                    }
                });
            });
        } else if (msg.type === 'control') {
            var decryptedMessage = server_private_key.decrypt(msg.message, 'utf8');
            decryptedMessage = JSON.parse(decryptedMessage);

            if (decryptedMessage.controlType === 'invite') {
                console.log(decryptedMessage);
                var usersNames = [];
                var usersNot = [];

                registeredUsers.forEach(function(user) {
                    if (user.online && decryptedMessage.message.includes(user.username) || user.username === decryptedMessage.requestingid) {
                        clients_inSession.push(user)
                        usersNames.push(user.username);

                    } else if (decryptedMessage.message.includes(user.username)) {
                        usersNot.push(user.username);
                    }
                });

                console.log(usersNames);

                console.log(clients_inSession);
                AES_SessionKey = crypto.randomBytes(16);
                AES_SessionKey = AES_SessionKey.toString('base64');
                console.log(AES_SessionKey);

                ws.clients.forEach(function(clientSocket) {
                    clients_inSession.forEach(function(user) {
                        if (clientSocket.userid === user.username) {
                            ciphertext = user.public_key.encrypt(JSON.stringify({
                                controlType: 'invite',
                                usersInSession: usersNames,
                                userNotInSession: usersNot,
                                sessionKey: AES_SessionKey,
                                requestingUser: decryptedMessage.requestingid
                            }), 'base64');

                            clientSocket.send(JSON.stringify({
                                type: 'control',
                                message: ciphertext
                            }));
                        }
                    });
                });

            } else if (decryptedMessage.controlType === 'showOnline') {
                var online_users = [];
                var public_key;

                // Find the users that are online
                registeredUsers.forEach(function(user) {
                    if (user.online) {
                        online_users.push(user.username);
                    }

                    if (user.username === decryptedMessage.userid) {
                        public_key = user.public_key;
                    }
                });

                ciphertext = public_key.encrypt(JSON.stringify({
                    controlType: 'showOnline',
                    users: online_users
                }), 'base64');

                socket.send(JSON.stringify({
                    type: 'control',
                    message: ciphertext
                }));

            } else if (decryptedMessage.controlType === 'quit') {
                registeredUsers.forEach(function(user) {
                    if (user.username === decryptedMessage.userid) {
                        user.online = false;
                        socket.userid = '';
                    }
                });
            } else {
                console.log('### Invalid Control Type:' + decryptedMessage.controlType + '###');
            }
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
    var message = 'Incorrect Login';
    // Make sure that the messages contains the correct fields
    if (!attempt.userid && !attempt.password) {
        message = 'Protocol not followed';
        return message;
    }

    // Find if the username and password are within the registeredUsers
    registeredUsers.forEach(function(user) {
        if ((user.username === attempt.userid) && (user.password === attempt.password)) {
            if (user.online) {
                message = 'Already logged in';
            } else {
                user.online = true;
                authenticated = true;
                message = user.public_key.encrypt(JSON.stringify({
                    nonce: nonceModify(attempt.nonce)
                }), 'base64');
            }
        }
    });
    return message;
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
