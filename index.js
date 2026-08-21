const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const db = new sqlite3.Database('./database.db');

// ======================================================
// SESSÕES
// ======================================================

const sessions = new Map();

function createSession(username) {
    const token = crypto.randomBytes(32).toString('hex');

    sessions.set(token, {
        username,
        createdAt: Date.now()
    });

    return token;
}

function getSession(req) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return null;
    }

    const match = cookies.match(/chat_session=([^;]+)/);

    if (!match) {
        return null;
    }

    return sessions.get(match[1]) || null;
}

function requireLogin(req, res, next) {
    const session = getSession(req);

    if (!session) {
        return res.redirect('/login.html');
    }

    req.username = session.username;
    next();
}

// ======================================================
// BANCO
// ======================================================

db.serialize(() => {

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            avatar TEXT DEFAULT ''
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT,
            user2 TEXT,
            status TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            message TEXT
        )
    `);

});

// ======================================================
// LOGIN / CADASTRO
// ======================================================

// Página de login
app.get('/login.html', (req, res) => {

    const session = getSession(req);

    if (session) {
        return res.redirect('/');
    }

    res.sendFile(__dirname + '/login.html');
});


// ======================================================
// CADASTRO
// ======================================================

app.post('/register', async (req, res) => {

    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || !password) {
        return res.status(400).send(
            'Preencha todos os campos.'
        );
    }

    if (username.length < 3) {
        return res.status(400).send(
            'O usuário precisa ter pelo menos 3 caracteres.'
        );
    }

    if (password.length < 4) {
        return res.status(400).send(
            'A senha precisa ter pelo menos 4 caracteres.'
        );
    }

    try {

        const hashedPassword =
            await bcrypt.hash(password, 10);

        db.run(
            `
            INSERT INTO users
            (username, password, avatar)
            VALUES (?, ?, '')
            `,
            [
                username,
                hashedPassword
            ],
            function(err) {

                if (err) {

                    if (
                        err.message &&
                        err.message.includes('UNIQUE')
                    ) {
                        return res.status(400).send(
                            'Usuário já existe!'
                        );
                    }

                    console.error(err);

                    return res.status(500).send(
                        'Erro ao criar conta.'
                    );
                }

                res.send(
                    'Conta criada com sucesso!'
                );
            }
        );

    } catch (error) {

        console.error(error);

        res.status(500).send(
            'Erro no servidor.'
        );
    }
});


// ======================================================
// LOGIN
// ======================================================

app.post('/login', (req, res) => {

    const username =
        String(req.body.username || '').trim();

    const password =
        String(req.body.password || '');

    if (!username || !password) {
        return res.status(400).send(
            'Preencha usuário e senha.'
        );
    }

    db.get(
        `
        SELECT *
        FROM users
        WHERE username = ?
        `,
        [username],
        async (err, user) => {

            if (err) {

                console.error(err);

                return res.status(500).send(
                    'Erro no servidor.'
                );
            }

            if (!user) {
                return res.status(401).send(
                    'Usuário ou senha incorretos!'
                );
            }

            try {

                const passwordCorrect =
                    await bcrypt.compare(
                        password,
                        user.password
                    );

                if (!passwordCorrect) {
                    return res.status(401).send(
                        'Usuário ou senha incorretos!'
                    );
                }

                const token =
                    createSession(user.username);

                res.setHeader(
                    'Set-Cookie',
                    `chat_session=${token}; HttpOnly; Path=/; SameSite=Lax`
                );

                res.json({
                    success: true,
                    username: user.username
                });

            } catch (error) {

                console.error(error);

                res.status(500).send(
                    'Erro no servidor.'
                );
            }
        }
    );
});


// ======================================================
// USUÁRIO LOGADO
// ======================================================

app.get('/me', (req, res) => {

    const session = getSession(req);

    if (!session) {

        return res.status(401).json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        username: session.username
    });
});


// ======================================================
// LOGOUT
// ======================================================

app.post('/logout', (req, res) => {

    const cookies = req.headers.cookie;

    if (cookies) {

        const match =
            cookies.match(/chat_session=([^;]+)/);

        if (match) {
            sessions.delete(match[1]);
        }
    }

    res.setHeader(
        'Set-Cookie',
        'chat_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
    );

    res.json({
        success: true
    });
});


// ======================================================
// PROTEGER O CHAT
// ======================================================

// IMPORTANTE:
// O login.html precisa continuar acessível.
// Tudo que estiver na raiz fica protegido.

app.get('/', requireLogin, (req, res) => {

    res.sendFile(
        __dirname + '/index.html'
    );
});


// ======================================================
// ARQUIVOS ESTÁTICOS
// ======================================================

// NÃO coloque express.static antes da proteção da raiz.
// Aqui liberamos somente arquivos necessários.

app.use('/css', express.static(__dirname + '/css'));
app.use('/js', express.static(__dirname + '/js'));
app.use('/assets', express.static(__dirname + '/assets'));


// ======================================================
// AVATAR
// ======================================================

app.post('/update-avatar', requireLogin, (req, res) => {

    const username = req.username;
    const avatar = req.body.avatar || '';

    db.run(
        `
        UPDATE users
        SET avatar = ?
        WHERE username = ?
        `,
        [avatar, username],
        function(err) {

            if (err) {

                console.error(err);

                return res.status(500).send(
                    'Erro ao atualizar avatar.'
                );
            }

            res.send(
                'Avatar atualizado com sucesso!'
            );
        }
    );
});


app.get('/user/:username', requireLogin, (req, res) => {

    const username = req.params.username;

    db.get(
        `
        SELECT username, avatar
        FROM users
        WHERE username = ?
        `,
        [username],
        (err, user) => {

            if (err || !user) {

                return res.json({
                    username,
                    avatar: ''
                });
            }

            res.json(user);
        }
    );
});


// ======================================================
// AMIGOS
// ======================================================

app.get('/friends/:username', requireLogin, (req, res) => {

    const username = req.params.username;

    db.all(
        `
        SELECT *
        FROM friendships
        WHERE user1 = ?
        OR user2 = ?
        `,
        [
            username,
            username
        ],
        (err, rows) => {

            if (err) {

                return res.status(500).send(
                    'Erro ao buscar amigos'
                );
            }

            const friendNames = [];
            const pendingNames = [];

            rows.forEach(row => {

                if (row.status === 'accepted') {

                    friendNames.push(
                        row.user1 === username
                            ? row.user2
                            : row.user1
                    );

                }

                else if (
                    row.status === 'pending' &&
                    row.user2 === username
                ) {

                    pendingNames.push(row.user1);
                }

            });


            const getDetails =
                (names, callback) => {

                    if (names.length === 0) {
                        return callback([]);
                    }

                    const placeholders =
                        names.map(() => '?').join(',');

                    db.all(
                        `
                        SELECT username, avatar
                        FROM users
                        WHERE username IN (${placeholders})
                        `,
                        names,
                        (err, results) => {

                            callback(
                                results || []
                            );
                        }
                    );
                };


            getDetails(
                friendNames,
                friends => {

                    getDetails(
                        pendingNames,
                        pendingRequests => {

                            res.json({
                                friends,
                                pendingRequests
                            });

                        }
                    );

                }
            );

        }
    );
});


// ======================================================
// ADICIONAR AMIGO
// ======================================================

app.post('/add-friend', requireLogin, (req, res) => {

    const username = req.username;

    const friendName =
        String(req.body.friendName || '').trim();

    if (!friendName) {
        return res.status(400).send(
            'Digite um usuário.'
        );
    }

    if (username === friendName) {

        return res.status(400).send(
            'Você não pode se adicionar.'
        );
    }

    db.get(
        `
        SELECT *
        FROM users
        WHERE username = ?
        `,
        [friendName],
        (err, user) => {

            if (!user) {

                return res.status(404).send(
                    'Usuário não encontrado!'
                );
            }

            db.get(
                `
                SELECT *
                FROM friendships
                WHERE
                (user1 = ? AND user2 = ?)
                OR
                (user1 = ? AND user2 = ?)
                `,
                [
                    username,
                    friendName,
                    friendName,
                    username
                ],
                (err, existing) => {

                    if (existing) {

                        if (
                            existing.status ===
                            'accepted'
                        ) {

                            return res.status(400).send(
                                'Vocês já são amigos.'
                            );
                        }

                        return res.status(400).send(
                            'Já existe um pedido pendente entre vocês.'
                        );
                    }

                    db.run(
                        `
                        INSERT INTO friendships
                        (user1, user2, status)
                        VALUES (?, ?, 'pending')
                        `,
                        [
                            username,
                            friendName
                        ],
                        err => {

                            if (err) {

                                return res.status(500).send(
                                    'Erro ao enviar pedido.'
                                );
                            }

                            res.send(
                                'Pedido de amizade enviado!'
                            );
                        }
                    );

                }
            );

        }
    );
});


// ======================================================
// ACEITAR AMIGO
// ======================================================

app.post('/accept-friend', requireLogin, (req, res) => {

    const username = req.username;

    const friendName =
        String(req.body.friendName || '').trim();

    db.run(
        `
        UPDATE friendships
        SET status = 'accepted'
        WHERE
        (user1 = ? AND user2 = ?)
        OR
        (user1 = ? AND user2 = ?)
        `,
        [
            friendName,
            username,
            username,
            friendName
        ],
        function(err) {

            if (err) {

                return res.status(400).send(
                    'Erro ao aceitar pedido.'
                );
            }

            res.send(
                'Pedido aceito!'
            );
        }
    );
});


// ======================================================
// REMOVER AMIGO
// ======================================================

app.post('/remove-friend', requireLogin, (req, res) => {

    const username = req.username;

    const friendName =
        String(req.body.friendName || '').trim();

    db.run(
        `
        DELETE FROM friendships
        WHERE
        (user1 = ? AND user2 = ?)
        OR
        (user1 = ? AND user2 = ?)
        `,
        [
            username,
            friendName,
            friendName,
            username
        ],
        err => {

            if (err) {

                return res.status(500).send(
                    'Erro ao remover amizade.'
                );
            }

            res.send(
                'Amizade removida.'
            );
        }
    );
});


// ======================================================
// SOCKET.IO
// ======================================================

const activeUsers = {};

io.on('connection', socket => {

    socket.callRoom = null;
    socket.username = null;


    // ==================================================
    // REGISTRAR USUÁRIO
    // ==================================================

    socket.on('register user', username => {

        if (!username) {
            return;
        }

        activeUsers[socket.id] = username;

        socket.username = username;

        socket.join(username);
    });


    // ==================================================
    // ATUALIZAR AMIGOS
    // ==================================================

    socket.on('notify update', targetUser => {

        if (!targetUser) {
            return;
        }

        io.to(targetUser).emit(
            'refresh friends'
        );
    });


    // ==================================================
    // FECHAR CHAT
    // ==================================================

    socket.on('force close chat', data => {

        if (!data) {
            return;
        }

        io.to(data.targetUser).emit(
            'close chat with',
            data.currentUser
        );
    });


    // ==================================================
    // ENTRAR NA SALA
    // ==================================================

    socket.on('join room', room => {

        if (!room) {
            return;
        }

        socket.rooms.forEach(r => {

            if (
                r !== socket.id &&
                r !== activeUsers[socket.id]
            ) {

                socket.leave(r);
            }

        });

        socket.join(room);

        const parts =
            room.includes('_')
                ? room.split('_')
                : room.split('-');

        if (parts.length < 2) {
            return;
        }

        db.all(
            `
            SELECT *
            FROM private_messages
            WHERE
            (sender = ? AND receiver = ?)
            OR
            (sender = ? AND receiver = ?)
            ORDER BY id ASC
            `,
            [
                parts[0],
                parts[1],
                parts[1],
                parts[0]
            ],
            (err, rows) => {

                if (err || !rows) {
                    return;
                }

                const sendWithAvatars =
                    async () => {

                        const enhancedRows = [];

                        for (
                            const msg of rows
                        ) {

                            await new Promise(
                                resolve => {

                                    db.get(
                                        `
                                        SELECT avatar
                                        FROM users
                                        WHERE username = ?
                                        `,
                                        [msg.sender],
                                        (err, u) => {

                                            enhancedRows.push({
                                                ...msg,
                                                avatar:
                                                    u
                                                        ? u.avatar
                                                        : ''
                                            });

                                            resolve();
                                        }
                                    );

                                }
                            );

                        }

                        socket.emit(
                            'load private history',
                            enhancedRows
                        );
                    };

                sendWithAvatars();

            }
        );

    });


    // ==================================================
    // MENSAGEM PRIVADA
    // ==================================================

    socket.on('private message', data => {

        if (!data) {
            return;
        }

        db.get(
            `
            SELECT avatar
            FROM users
            WHERE username = ?
            `,
            [data.sender],
            (err, userRow) => {

                const senderAvatar =
                    userRow
                        ? userRow.avatar
                        : '';

                db.run(
                    `
                    INSERT INTO private_messages
                    (sender, receiver, message)
                    VALUES (?, ?, ?)
                    `,
                    [
                        data.sender,
                        data.receiver,
                        data.message
                    ],
                    err => {

                        if (err) {
                            return;
                        }

                        io.to(data.room).emit(
                            'private message',
                            {
                                ...data,
                                avatar: senderAvatar
                            }
                        );


                        const receiverSockets =
                            io.sockets.adapter.rooms.get(
                                data.receiver
                            );

                        if (receiverSockets) {

                            for (
                                const socketId
                                of receiverSockets
                            ) {

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
                                            avatar:
                                                senderAvatar
                                        }
                                    );
                                }

                            }

                        }

                    }
                );

            }
        );
    });


    // ==================================================
    // CALL OFFER
    // ==================================================

    socket.on('call-offer', data => {

        if (!data || !data.room) {
            return;
        }

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'call-offer',
            data
        );
    });


    // ==================================================
    // CALL ANSWER
    // ==================================================

    socket.on('call-answer', data => {

        if (!data || !data.room) {
            return;
        }

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'call-answer',
            data
        );
    });


    // ==================================================
    // RENEGOTIATION OFFER
    // ==================================================

    socket.on('renegotiation-offer', data => {

        if (!data || !data.room) {
            return;
        }

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'renegotiation-offer',
            data
        );
    });


    // ==================================================
    // RENEGOTIATION ANSWER
    // ==================================================

    socket.on('renegotiation-answer', data => {

        if (!data || !data.room) {
            return;
        }

        socket.callRoom = data.room;

        socket.to(data.room).emit(
            'renegotiation-answer',
            data
        );
    });


    // ==================================================
    // ICE
    // ==================================================

    socket.on('ice-candidate', data => {

        if (!data || !data.room) {
            return;
        }

        socket.to(data.room).emit(
            'ice-candidate',
            data
        );
    });


    // ==================================================
    // DESLIGAR CHAMADA
    // ==================================================

    socket.on('hang-up', data => {

        if (!data || !data.room) {
            return;
        }

        if (socket.callRoom === data.room) {
            socket.callRoom = null;
        }

        socket.to(data.room).emit(
            'hang-up'
        );
    });


    // ==================================================
    // TRANSMISSÃO DE TELA PAROU
    // ==================================================

    socket.on('screen-stopped', data => {

        if (!data || !data.room) {
            return;
        }

        socket.to(data.room).emit(
            'screen-stopped'
        );
    });


    // ==================================================
    // DESCONECTOU
    // ==================================================

    socket.on('disconnect', () => {

        const username =
            activeUsers[socket.id];

        if (socket.callRoom) {

            socket.to(
                socket.callRoom
            ).emit('hang-up');

        }

        delete activeUsers[socket.id];
    });

});


// ======================================================
// SERVIDOR
// ======================================================

const PORT =
    process.env.PORT || 3000;

server.listen(
    PORT,
    '0.0.0.0',
    () => {

        console.log(
            `Servidor rodando na porta ${PORT}`
        );

    }
);
