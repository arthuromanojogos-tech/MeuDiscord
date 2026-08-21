const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static(__dirname));

const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        avatar TEXT DEFAULT ''
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1 TEXT,
        user2 TEXT,
        status TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT
    )`);
});


// ===============================
// CADASTRO
// ===============================

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Preencha todos os campos.");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            `INSERT INTO users (username, password, avatar) VALUES (?, ?, '')`,
            [username, hashedPassword],
            (err) => {
                if (err) {
                    return res.status(400).send("Usuário já existe!");
                }

                res.send("Cadastrado com sucesso!");
            }
        );
    } catch (e) {
        res.status(500).send("Erro no servidor.");
    }
});


// ===============================
// LOGIN
// ===============================

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        async (err, user) => {

            if (
                !user ||
                !(await bcrypt.compare(password, user.password))
            ) {
                return res.status(401).send("Login inválido!");
            }

            res.send("Logado!");
        }
    );
});


// ===============================
// AVATAR
// ===============================

app.post('/update-avatar', (req, res) => {
    const { username, avatar } = req.body;

    db.run(
        `UPDATE users SET avatar = ? WHERE username = ?`,
        [avatar, username],
        function(err) {

            if (err) {
                return res.status(500).send(
                    "Erro ao atualizar avatar."
                );
            }

            res.send("Avatar atualizado com sucesso!");
        }
    );
});


app.get('/user/:username', (req, res) => {

    const username = req.params.username;

    db.get(
        `SELECT username, avatar FROM users WHERE username = ?`,
        [username],
        (err, user) => {

            if (err || !user) {
                return res.json({
                    username: username,
                    avatar: ''
                });
            }

            res.json(user);
        }
    );
});


// ===============================
// AMIGOS
// ===============================

app.get('/friends/:username', (req, res) => {

    const username = req.params.username;

    db.all(
        `SELECT * FROM friendships
         WHERE (user1 = ? OR user2 = ?)`,
        [username, username],
        (err, rows) => {

            if (err) {
                return res.status(500).send(
                    "Erro ao buscar amigos"
                );
            }

            let friendNames = [];
            let pendingNames = [];

            rows.forEach(row => {

                if (row.status === 'accepted') {

                    friendNames.push(
                        row.user1 === username
                            ? row.user2
                            : row.user1
                    );

                } else if (
                    row.status === 'pending' &&
                    row.user2 === username
                ) {

                    pendingNames.push(row.user1);
                }
            });


            const getDetails = (names, callback) => {

                if (names.length === 0) {
                    return callback([]);
                }

                const placeholders =
                    names.map(() => '?').join(',');

                db.all(
                    `SELECT username, avatar
                     FROM users
                     WHERE username IN (${placeholders})`,
                    names,
                    (err, results) => {
                        callback(results || []);
                    }
                );
            };


            getDetails(friendNames, (friends) => {

                getDetails(
                    pendingNames,
                    (pendingRequests) => {

                        res.json({
                            friends,
                            pendingRequests
                        });

                    }
                );

            });

        }
    );
});


app.post('/add-friend', (req, res) => {

    const { username, friendName } = req.body;

    if (username === friendName) {
        return res.status(400).send(
            "Você não pode se adicionar."
        );
    }

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [friendName],
        (err, user) => {

            if (!user) {
                return res.status(404).send(
                    "Usuário não encontrado!"
                );
            }


            db.get(
                `SELECT * FROM friendships
                 WHERE
                 (user1 = ? AND user2 = ?)
                 OR
                 (user1 = ? AND user2 = ?)`,
                [
                    username,
                    friendName,
                    friendName,
                    username
                ],
                (err, existing) => {

                    if (existing) {

                        if (existing.status === 'accepted') {
                            return res.status(400).send(
                                "Vocês já são amigos."
                            );
                        }

                        return res.status(400).send(
                            "Já existe um pedido pendente entre vocês."
                        );
                    }


                    db.run(
                        `INSERT INTO friendships
                         (user1, user2, status)
                         VALUES (?, ?, 'pending')`,
                        [
                            username,
                            friendName
                        ],
                        (err) => {

                            if (err) {
                                return res.status(500).send(
                                    "Erro ao enviar pedido."
                                );
                            }

                            res.send(
                                "Pedido de amizade enviado!"
                            );
                        }
                    );

                }
            );

        }
    );
});


app.post('/accept-friend', (req, res) => {

    const { username, friendName } = req.body;

    db.run(
        `UPDATE friendships
         SET status = 'accepted'
         WHERE
         (user1 = ? AND user2 = ?)
         OR
         (user1 = ? AND user2 = ?)`,
        [
            friendName,
            username,
            username,
            friendName
        ],
        function(err) {

            if (err) {
                return res.status(400).send(
                    "Erro ao aceitar pedido."
                );
            }

            res.send("Pedido aceito!");
        }
    );
});


app.post('/remove-friend', (req, res) => {

    const { username, friendName } = req.body;

    db.run(
        `DELETE FROM friendships
         WHERE
         (user1 = ? AND user2 = ?)
         OR
         (user1 = ? AND user2 = ?)`,
        [
            username,
            friendName,
            friendName,
            username
        ],
        (err) => {

            if (err) {
                return res.status(500).send(
                    "Erro ao remover amizade."
                );
            }

            res.send("Amizade removida.");
        }
    );
});


// ===============================
// SOCKET.IO
// ===============================

const activeUsers = {};

io.on('connection', (socket) => {

    socket.callRoom = null;
    socket.username = null;


    // ===============================
    // REGISTRAR USUÁRIO
    // ===============================

    socket.on('register user', (username) => {

        activeUsers[socket.id] = username;
        socket.username = username;

        socket.join(username);
    });


    // ===============================
    // ATUALIZAR AMIGOS
    // ===============================

    socket.on('notify update', (targetUser) => {

        io.to(targetUser).emit('refresh friends');
    });


    // ===============================
    // FECHAR CHAT
    // ===============================

    socket.on('force close chat', (data) => {

        if (!data) return;

        io.to(data.targetUser).emit(
            'close chat with',
            data.currentUser
        );
    });


    // ===============================
    // ENTRAR NA SALA
    // ===============================

    socket.on('join room', (room) => {

        socket.rooms.forEach(r => {

            if (
                r !== socket.id &&
                r !== activeUsers[socket.id]
            ) {
                socket.leave(r);
            }

        });

        socket.join(room);


        const parts = room.includes('_')
            ? room.split('_')
            : room.split('-');


        if (parts.length < 2) return;


        db.all(
            `SELECT *
             FROM private_messages
             WHERE
             (sender = ? AND receiver = ?)
             OR
             (sender = ? AND receiver = ?)
             ORDER BY id ASC`,
            [
                parts[0],
                parts[1],
                parts[1],
                parts[0]
            ],
            (err, rows) => {

                if (!err && rows) {

                    const sendWithAvatars = async () => {

                        const enhancedRows = [];

                        for (let msg of rows) {

                            await new Promise((resolve) => {

                                db.get(
                                    `SELECT avatar
                                     FROM users
                                     WHERE username = ?`,
                                    [msg.sender],
                                    (err, u) => {

                                        enhancedRows.push({
                                            ...msg,
                                            avatar: u
                                                ? u.avatar
                                                : ''
                                        });

                                        resolve();
                                    }
                                );

                            });

                        }

                        socket.emit(
                            'load private history',
                            enhancedRows
                        );
                    };

                    sendWithAvatars();
                }
            }
        );
    });


    // ===============================
    // MENSAGEM PRIVADA
    // ===============================

    socket.on('private message', (data) => {

        db.get(
            `SELECT avatar
             FROM users
             WHERE username = ?`,
            [data.sender],
            (err, userRow) => {

                const senderAvatar =
                    userRow ? userRow.avatar : '';

                db.run(
                    `INSERT INTO private_messages
                     (sender, receiver, message)
                     VALUES (?, ?, ?)`,
                    [
                        data.sender,
                        data.receiver,
                        data.message
                    ],
                    (err) => {

                        if (!err) {

                            // Envia para todos que estão
                            // dentro da sala da conversa.
                            io.to(data.room).emit(
                                'private message',
                                {
                                    ...data,
                                    avatar: senderAvatar
                                }
                            );


                            // Se o destinatário estiver conectado,
                            // mas NÃO estiver dentro da sala,
                            // envia a mensagem diretamente para ele.
                            const receiverSockets =
                                io.sockets.adapter.rooms.get(
                                    data.receiver
                                );

                            if (receiverSockets) {

                                for (const socketId of receiverSockets) {

                                    const receiverSocket =
                                        io.sockets.sockets.get(
                                            socketId
                                        );

                                    if (
                                        receiverSocket &&
                                        !receiverSocket.rooms.has(
                                            data.room
                                        )
                                    ) {

                                        receiverSocket.emit(
                                            'private message',
                                            {
                                                ...data,
                                                avatar: senderAvatar
                                            }
                                        );

                                    }

                                }

                            }

                        }

                    }
                );

            }
        );
    });


    // ===============================
    // CHAMADA - OFFER
    // ===============================

    socket.on('call-offer', (data) => {

        if (!data || !data.room) return;

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'call-offer',
            data
        );
    });


    // ===============================
    // CHAMADA - ANSWER
    // ===============================

    socket.on('call-answer', (data) => {

        if (!data || !data.room) return;

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'call-answer',
            data
        );
    });


    // ===============================
    // RENEGOCIAÇÃO - OFFER
    // ===============================

    socket.on('renegotiation-offer', (data) => {

        if (!data || !data.room) return;

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'renegotiation-offer',
            data
        );
    });


    // ===============================
    // RENEGOCIAÇÃO - ANSWER
    // ===============================

    socket.on('renegotiation-answer', (data) => {

        if (!data || !data.room) return;

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'renegotiation-answer',
            data
        );
    });


    // ===============================
    // ICE
    // ===============================

    socket.on('ice-candidate', (data) => {

        if (!data || !data.room) return;

        socket.to(data.room).emit(
            'ice-candidate',
            data
        );
    });


    // ===============================
    // DESLIGAR CHAMADA
    // ===============================

    socket.on('hang-up', (data) => {

        if (!data || !data.room) return;

        if (socket.callRoom === data.room) {
            socket.callRoom = null;
        }

        socket.to(data.room).emit('hang-up');
    });

// ===============================
// TRANSMISSÃO DE TELA PAROU
// ===============================

socket.on('screen-stopped', (data) => {

    if (!data || !data.room) {
        return;
    }

    socket.to(data.room).emit(
        'screen-stopped'
    );

});

    
    // ===============================
    // DESCONECTOU
    // ===============================

    socket.on('disconnect', () => {

        const username = activeUsers[socket.id];

        if (socket.callRoom) {
            socket.to(socket.callRoom).emit('hang-up');
        }

        delete activeUsers[socket.id];
    });

});


// ===============================
// SERVIDOR
// ===============================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
