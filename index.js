const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

/*
======================================================
CONFIGURAÇÃO
======================================================
*/

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL ||
    'https://meudiscord.onrender.com';

/*
Origens permitidas.

O Capacitor pode usar:
- capacitor://localhost
- http://localhost
- https://localhost

Dependendo de como o Android/iOS estiver configurado.
*/

const allowedOrigins = [
    'https://meudiscord.onrender.com',
    'capacitor://localhost',
    'http://localhost',
    'https://localhost',
    'http://127.0.0.1',
    'http://192.168.0.1',
    'http://192.168.1.1'
];

/*
======================================================
CORS
======================================================
*/

function checkOrigin(origin, callback) {

    // Requisições sem Origin normalmente são permitidas.
    if (!origin) {
        return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
        return callback(null, true);
    }

    /*
    Durante desenvolvimento, permitir localhost
    com qualquer porta.
    */

    if (
        /^http:\/\/localhost(:\d+)?$/.test(origin) ||
        /^https:\/\/localhost(:\d+)?$/.test(origin) ||
        /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)
    ) {
        return callback(null, true);
    }

    console.log('CORS bloqueou:', origin);

    callback(new Error('Origem não permitida pelo CORS'));
}

app.use((req, res, next) => {

    const origin = req.headers.origin;

    if (origin) {

        if (
            allowedOrigins.includes(origin) ||
            /^http:\/\/localhost(:\d+)?$/.test(origin) ||
            /^https:\/\/localhost(:\d+)?$/.test(origin) ||
            /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)
        ) {

            res.header(
                'Access-Control-Allow-Origin',
                origin
            );

            res.header(
                'Access-Control-Allow-Credentials',
                'true'
            );

            res.header(
                'Access-Control-Allow-Methods',
                'GET,POST,PUT,DELETE,OPTIONS'
            );

            res.header(
                'Access-Control-Allow-Headers',
                'Content-Type, Authorization'
            );
        }
    }

    if (req.method === 'OPTIONS') {

        return res.sendStatus(204);
    }

    next();
});

/*
======================================================
EXPRESS
======================================================
*/

app.use(express.json({
    limit: '10mb'
}));

app.use(express.urlencoded({
    limit: '10mb',
    extended: true
}));

/*
======================================================
SOCKET.IO
======================================================
*/

const io = new Server(server, {

    cors: {
        origin: checkOrigin,
        credentials: true,
        methods: [
            'GET',
            'POST'
        ]
    },

    transports: [
        'websocket',
        'polling'
    ]
});

/*
======================================================
BANCO
======================================================
*/

const db = new sqlite3.Database(
    './database.db',
    err => {

        if (err) {
            console.error(
                'Erro ao abrir banco:',
                err
            );
        } else {
            console.log(
                'Banco SQLite conectado.'
            );
        }

    }
);

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

/*
======================================================
SESSÕES
======================================================
*/

const sessions = new Map();

function createSession(username) {

    const token =
        crypto.randomBytes(32).toString('hex');

    sessions.set(token, {

        username,

        createdAt: Date.now()

    });

    return token;
}

function getSession(req) {

    const cookies =
        req.headers.cookie;

    if (!cookies) {
        return null;
    }

    const match =
        cookies.match(
            /(?:^|;\s*)chat_session=([^;]+)/
        );

    if (!match) {
        return null;
    }

    return sessions.get(
        match[1]
    ) || null;
}

function requireLogin(req, res, next) {

    const session =
        getSession(req);

    if (!session) {

        return res.status(401).json({
            success: false,
            loggedIn: false,
            message: 'Não autenticado.'
        });
    }

    req.username =
        session.username;

    next();
}

/*
======================================================
LOGIN PAGE
======================================================
*/

app.get('/login.html', (req, res) => {

    const session =
        getSession(req);

    if (session) {
        return res.redirect('/');
    }

    res.sendFile(
        __dirname + '/login.html'
    );
});

/*
======================================================
CADASTRO
======================================================
*/

app.post('/register', async (req, res) => {

    const username =
        String(
            req.body.username || ''
        ).trim();

    const password =
        String(
            req.body.password || ''
        );

    if (!username || !password) {

        return res.status(400).json({
            success: false,
            message:
                'Preencha todos os campos.'
        });
    }

    if (username.length < 3) {

        return res.status(400).json({
            success: false,
            message:
                'O usuário precisa ter pelo menos 3 caracteres.'
        });
    }

    if (password.length < 4) {

        return res.status(400).json({
            success: false,
            message:
                'A senha precisa ter pelo menos 4 caracteres.'
        });
    }

    try {

        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );

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

                        return res.status(400).json({
                            success: false,
                            message:
                                'Usuário já existe!'
                        });
                    }

                    console.error(
                        'Erro no cadastro:',
                        err
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao criar conta.'
                    });
                }

                return res.json({

                    success: true,

                    message:
                        'Conta criada com sucesso!',

                    username

                });

            }
        );

    } catch (error) {

        console.error(
            'Erro no cadastro:',
            error
        );

        return res.status(500).json({
            success: false,
            message:
                'Erro no servidor.'
        });
    }
});

/*
======================================================
LOGIN
======================================================
*/

app.post('/login', (req, res) => {

    const username =
        String(
            req.body.username || ''
        ).trim();

    const password =
        String(
            req.body.password || ''
        );

    if (!username || !password) {

        return res.status(400).json({
            success: false,
            message:
                'Preencha usuário e senha.'
        });
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

                console.error(
                    'Erro no login:',
                    err
                );

                return res.status(500).json({
                    success: false,
                    message:
                        'Erro no servidor.'
                });
            }

            if (!user) {

                return res.status(401).json({
                    success: false,
                    message:
                        'Usuário ou senha incorretos!'
                });
            }

            try {

                const passwordCorrect =
                    await bcrypt.compare(
                        password,
                        user.password
                    );

                if (!passwordCorrect) {

                    return res.status(401).json({
                        success: false,
                        message:
                            'Usuário ou senha incorretos!'
                    });
                }

                const token =
                    createSession(
                        user.username
                    );

                /*
                Para o site e para o Capacitor.

                SameSite=None permite que o cookie
                seja enviado em requisições vindas
                do aplicativo.

                Secure exige HTTPS.
                */

                res.setHeader(
                    'Set-Cookie',
                    [
                        `chat_session=${token}`,
                        'HttpOnly',
                        'Path=/',
                        'Max-Age=2592000',
                        'SameSite=None',
                        'Secure'
                    ].join('; ')
                );

                return res.json({

                    success: true,

                    loggedIn: true,

                    username:
                        user.username

                });

            } catch (error) {

                console.error(
                    'Erro ao comparar senha:',
                    error
                );

                return res.status(500).json({
                    success: false,
                    message:
                        'Erro no servidor.'
                });
            }
        }
    );
});

/*
======================================================
USUÁRIO LOGADO
======================================================
*/

app.get('/me', (req, res) => {

    const session =
        getSession(req);

    if (!session) {

        return res.status(401).json({

            success: false,

            loggedIn: false

        });
    }

    db.get(
        `
        SELECT username, avatar
        FROM users
        WHERE username = ?
        `,
        [session.username],
        (err, user) => {

            if (err) {

                return res.status(500).json({
                    success: false,
                    loggedIn: false
                });
            }

            return res.json({

                success: true,

                loggedIn: true,

                username:
                    session.username,

                avatar:
                    user
                        ? user.avatar
                        : ''

            });

        }
    );
});

/*
======================================================
LOGOUT
======================================================
*/

app.post('/logout', (req, res) => {

    const cookies =
        req.headers.cookie;

    if (cookies) {

        const match =
            cookies.match(
                /(?:^|;\s*)chat_session=([^;]+)/
            );

        if (match) {

            sessions.delete(
                match[1]
            );
        }
    }

    res.setHeader(
        'Set-Cookie',
        [
            'chat_session=',
            'HttpOnly',
            'Path=/',
            'Max-Age=0',
            'SameSite=None',
            'Secure'
        ].join('; ')
    );

    return res.json({
        success: true
    });
});

/*
======================================================
CHAT
======================================================
*/

app.get('/', (req, res) => {

    const session =
        getSession(req);

    if (!session) {

        return res.redirect(
            '/login.html'
        );
    }

    res.sendFile(
        __dirname + '/index.html'
    );
});

/*
======================================================
ARQUIVOS ESTÁTICOS
======================================================
*/

app.use(
    '/css',
    express.static(
        __dirname + '/css'
    )
);

app.use(
    '/js',
    express.static(
        __dirname + '/js'
    )
);

app.use(
    '/assets',
    express.static(
        __dirname + '/assets'
    )
);

/*
======================================================
AVATAR
======================================================
*/

app.post(
    '/update-avatar',
    requireLogin,
    (req, res) => {

        const username =
            req.username;

        const avatar =
            String(
                req.body.avatar || ''
            );

        db.run(
            `
            UPDATE users
            SET avatar = ?
            WHERE username = ?
            `,
            [
                avatar,
                username
            ],
            function(err) {

                if (err) {

                    console.error(
                        'Erro avatar:',
                        err
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao atualizar avatar.'
                    });
                }

                return res.json({
                    success: true,
                    message:
                        'Avatar atualizado com sucesso!'
                });

            }
        );
    }
);

/*
======================================================
USUÁRIO
======================================================
*/

app.get(
    '/user/:username',
    requireLogin,
    (req, res) => {

        const username =
            req.params.username;

        db.get(
            `
            SELECT username, avatar
            FROM users
            WHERE username = ?
            `,
            [username],
            (err, user) => {

                if (err) {

                    return res.status(500).json({
                        success: false
                    });
                }

                if (!user) {

                    return res.json({

                        username,

                        avatar: ''

                    });
                }

                return res.json(user);
            }
        );
    }
);

/*
======================================================
AMIGOS
======================================================
*/

app.get(
    '/friends/:username',
    requireLogin,
    (req, res) => {

        const username =
            req.params.username;

        /*
        Impede que uma pessoa consulte
        a lista de outro usuário.
        */

        if (
            username !== req.username
        ) {

            return res.status(403).json({
                success: false,
                message:
                    'Acesso negado.'
            });
        }

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

                    console.error(
                        'Erro amigos:',
                        err
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao buscar amigos.'
                    });
                }

                const friendNames = [];
                const pendingNames = [];

                rows.forEach(row => {

                    if (
                        row.status ===
                        'accepted'
                    ) {

                        friendNames.push(
                            row.user1 === username
                                ? row.user2
                                : row.user1
                        );
                    }

                    else if (
                        row.status ===
                            'pending' &&
                        row.user2 === username
                    ) {

                        pendingNames.push(
                            row.user1
                        );
                    }

                });

                const getDetails =
                    (names, callback) => {

                        if (
                            names.length === 0
                        ) {

                            return callback([]);
                        }

                        const placeholders =
                            names
                                .map(() => '?')
                                .join(',');

                        db.all(
                            `
                            SELECT username, avatar
                            FROM users
                            WHERE username IN (${placeholders})
                            `,
                            names,
                            (err, results) => {

                                if (err) {

                                    return callback([]);
                                }

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

                                return res.json({

                                    success: true,

                                    friends,

                                    pendingRequests

                                });

                            }
                        );
                    }
                );
            }
        );
    }
);

/*
======================================================
ADICIONAR AMIGO
======================================================
*/

app.post(
    '/add-friend',
    requireLogin,
    (req, res) => {

        const username =
            req.username;

        const friendName =
            String(
                req.body.friendName || ''
            ).trim();

        if (!friendName) {

            return res.status(400).json({
                success: false,
                message:
                    'Digite um usuário.'
            });
        }

        if (
            username === friendName
        ) {

            return res.status(400).json({
                success: false,
                message:
                    'Você não pode se adicionar.'
            });
        }

        db.get(
            `
            SELECT username
            FROM users
            WHERE username = ?
            `,
            [friendName],
            (err, user) => {

                if (err) {

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao procurar usuário.'
                    });
                }

                if (!user) {

                    return res.status(404).json({
                        success: false,
                        message:
                            'Usuário não encontrado!'
                    });
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

                        if (err) {

                            return res.status(500).json({
                                success: false,
                                message:
                                    'Erro ao verificar amizade.'
                            });
                        }

                        if (existing) {

                            if (
                                existing.status ===
                                'accepted'
                            ) {

                                return res.status(400).json({
                                    success: false,
                                    message:
                                        'Vocês já são amigos.'
                                });
                            }

                            return res.status(400).json({
                                success: false,
                                message:
                                    'Já existe um pedido pendente entre vocês.'
                            });
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

                                    console.error(
                                        'Erro amizade:',
                                        err
                                    );

                                    return res.status(500).json({
                                        success: false,
                                        message:
                                            'Erro ao enviar pedido.'
                                    });
                                }

                                /*
                                Atualiza o outro usuário
                                em tempo real.
                                */

                                io.to(
                                    friendName
                                ).emit(
                                    'refresh friends'
                                );

                                return res.json({
                                    success: true,
                                    message:
                                        'Pedido de amizade enviado!'
                                });
                            }
                        );
                    }
                );
            }
        );
    }
);

/*
======================================================
ACEITAR AMIGO
======================================================
*/

app.post(
    '/accept-friend',
    requireLogin,
    (req, res) => {

        const username =
            req.username;

        const friendName =
            String(
                req.body.friendName || ''
            ).trim();

        db.run(
            `
            UPDATE friendships
            SET status = 'accepted'
            WHERE
            user1 = ?
            AND user2 = ?
            AND status = 'pending'
            `,
            [
                friendName,
                username
            ],
            function(err) {

                if (err) {

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao aceitar pedido.'
                    });
                }

                if (this.changes === 0) {

                    return res.status(400).json({
                        success: false,
                        message:
                            'Pedido de amizade não encontrado.'
                    });
                }

                io.to(
                    friendName
                ).emit(
                    'refresh friends'
                );

                io.to(
                    username
                ).emit(
                    'refresh friends'
                );

                return res.json({
                    success: true,
                    message:
                        'Pedido aceito!'
                });
            }
        );
    }
);

/*
======================================================
REMOVER AMIGO
======================================================
*/

app.post(
    '/remove-friend',
    requireLogin,
    (req, res) => {

        const username =
            req.username;

        const friendName =
            String(
                req.body.friendName || ''
            ).trim();

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
            function(err) {

                if (err) {

                    return res.status(500).json({
                        success: false,
                        message:
                            'Erro ao remover amizade.'
                    });
                }

                io.to(
                    friendName
                ).emit(
                    'refresh friends'
                );

                io.to(
                    username
                ).emit(
                    'refresh friends'
                );

                return res.json({
                    success: true,
                    message:
                        'Amizade removida.'
                });
            }
        );
    }
);

/*
======================================================
SOCKET.IO
======================================================
*/

const activeUsers = {};

io.on(
    'connection',
    socket => {

        console.log(
            'Socket conectado:',
            socket.id
        );

        socket.callRoom = null;
        socket.username = null;

        /*
        ==============================================
        REGISTRAR USUÁRIO
        ==============================================
        */

        socket.on(
            'register user',
            username => {

                if (!username) {
                    return;
                }

                username =
                    String(
                        username
                    ).trim();

                if (!username) {
                    return;
                }

                activeUsers[
                    socket.id
                ] = username;

                socket.username =
                    username;

                socket.join(
                    username
                );

                console.log(
                    'Usuário conectado:',
                    username
                );
            }
        );

        /*
        ==============================================
        ATUALIZAR AMIGOS
        ==============================================
        */

        socket.on(
            'notify update',
            targetUser => {

                if (!targetUser) {
                    return;
                }

                io.to(
                    targetUser
                ).emit(
                    'refresh friends'
                );
            }
        );

        /*
        ==============================================
        FECHAR CHAT
        ==============================================
        */

        socket.on(
            'force close chat',
            data => {

                if (!data) {
                    return;
                }

                if (!data.targetUser) {
                    return;
                }

                io.to(
                    data.targetUser
                ).emit(
                    'close chat with',
                    data.currentUser
                );
            }
        );

        /*
        ==============================================
        ENTRAR NA SALA
        ==============================================
        */

        socket.on(
            'join room',
            room => {

                if (!room) {
                    return;
                }

                /*
                Sai de salas antigas,
                mas mantém:
                - socket.id
                - sala do usuário
                */

                [...socket.rooms].forEach(
                    r => {

                        if (
                            r !== socket.id &&
                            r !== socket.username
                        ) {

                            socket.leave(r);
                        }
                    }
                );

                socket.join(room);

                const parts =
                    room.includes('_')
                        ? room.split('_')
                        : room.split('-');

                if (
                    parts.length < 2
                ) {
                    return;
                }

                const user1 =
                    parts[0];

                const user2 =
                    parts[1];

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
                        user1,
                        user2,
                        user2,
                        user1
                    ],
                    (err, rows) => {

                        if (
                            err ||
                            !rows
                        ) {
                            return;
                        }

                        const enhancedRows = [];

                        if (
                            rows.length === 0
                        ) {

                            return socket.emit(
                                'load private history',
                                []
                            );
                        }

                        let completed = 0;

                        rows.forEach(
                            msg => {

                                db.get(
                                    `
                                    SELECT avatar
                                    FROM users
                                    WHERE username = ?
                                    `,
                                    [
                                        msg.sender
                                    ],
                                    (avatarErr, user) => {

                                        enhancedRows.push({

                                            ...msg,

                                            avatar:
                                                user
                                                    ? user.avatar
                                                    : ''

                                        });

                                        completed++;

                                        if (
                                            completed ===
                                            rows.length
                                        ) {

                                            enhancedRows.sort(
                                                (a, b) =>
                                                    a.id - b.id
                                            );

                                            socket.emit(
                                                'load private history',
                                                enhancedRows
                                            );
                                        }
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );

        /*
        ==============================================
        MENSAGEM PRIVADA
        ==============================================
        */

        socket.on(
            'private message',
            data => {

                if (!data) {
                    return;
                }

                if (
                    !data.sender ||
                    !data.receiver ||
                    !data.message
                ) {
                    return;
                }

                const sender =
                    String(
                        data.sender
                    ).trim();

                const receiver =
                    String(
                        data.receiver
                    ).trim();

                const message =
                    String(
                        data.message
                    );

                if (
                    !sender ||
                    !receiver ||
                    !message
                ) {
                    return;
                }

                db.get(
                    `
                    SELECT avatar
                    FROM users
                    WHERE username = ?
                    `,
                    [sender],
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
                                sender,
                                receiver,
                                message
                            ],
                            function(err) {

                                if (err) {

                                    console.error(
                                        'Erro mensagem:',
                                        err
                                    );

                                    return;
                                }

                                const messageData = {

                                    id: this.lastID,

                                    sender,

                                    receiver,

                                    message,

                                    room:
                                        data.room,

                                    avatar:
                                        senderAvatar

                                };

                                /*
                                Envia para quem está
                                na sala.
                                */

                                if (
                                    data.room
                                ) {

                                    io.to(
                                        data.room
                                    ).emit(
                                        'private message',
                                        messageData
                                    );
                                }

                                /*
                                Se o receptor não estiver
                                na sala, envia diretamente
                                para o usuário.
                                */

                                const receiverSockets =
                                    io.sockets.adapter.rooms.get(
                                        receiver
                                    );

                                if (
                                    receiverSockets
                                ) {

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
                                            data.room &&
                                            !receiverSocket.rooms.has(
                                                data.room
                                            )
                                        ) {

                                            receiverSocket.emit(
                                                'private message',
                                                messageData
                                            );
                                        }
                                    }
                                }
                            }
                        );
                    }
                );
            }
        );

        /*
        ==============================================
        CALL OFFER
        ==============================================
        */

        socket.on(
            'call-offer',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.callRoom =
                    data.room;

                socket.to(
                    data.room
                ).emit(
                    'call-offer',
                    data
                );
            }
        );

        /*
        ==============================================
        CALL ANSWER
        ==============================================
        */

        socket.on(
            'call-answer',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.callRoom =
                    data.room;

                socket.to(
                    data.room
                ).emit(
                    'call-answer',
                    data
                );
            }
        );

        /*
        ==============================================
        RENEGOTIATION OFFER
        ==============================================
        */

        socket.on(
            'renegotiation-offer',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.callRoom =
                    data.room;

                socket.to(
                    data.room
                ).emit(
                    'renegotiation-offer',
                    data
                );
            }
        );

        /*
        ==============================================
        RENEGOTIATION ANSWER
        ==============================================
        */

        socket.on(
            'renegotiation-answer',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.callRoom =
                    data.room;

                socket.to(
                    data.room
                ).emit(
                    'renegotiation-answer',
                    data
                );
            }
        );

        /*
        ==============================================
        ICE
        ==============================================
        */

        socket.on(
            'ice-candidate',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.to(
                    data.room
                ).emit(
                    'ice-candidate',
                    data
                );
            }
        );

        /*
        ==============================================
        DESLIGAR
        ==============================================
        */

        socket.on(
            'hang-up',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                if (
                    socket.callRoom ===
                    data.room
                ) {

                    socket.callRoom =
                        null;
                }

                socket.to(
                    data.room
                ).emit(
                    'hang-up'
                );
            }
        );

        /*
        ==============================================
        TRANSMISSÃO DE TELA PAROU
        ==============================================
        */

        socket.on(
            'screen-stopped',
            data => {

                if (
                    !data ||
                    !data.room
                ) {
                    return;
                }

                socket.to(
                    data.room
                ).emit(
                    'screen-stopped'
                );
            }
        );

        /*
        ==============================================
        DESCONECTOU
        ==============================================
        */

        socket.on(
            'disconnect',
            reason => {

                const username =
                    activeUsers[
                        socket.id
                    ];

                console.log(
                    'Socket desconectado:',
                    username || socket.id,
                    reason
                );

                if (
                    socket.callRoom
                ) {

                    socket.to(
                        socket.callRoom
                    ).emit(
                        'hang-up'
                    );
                }

                delete activeUsers[
                    socket.id
                ];
            }
        );
    }
);

/*
======================================================
 HEALTH CHECK
======================================================
*/

app.get(
    '/health',
    (req, res) => {

        res.json({

            success: true,

            server: 'Meu Discord',

            status: 'online',

            time:
                new Date().toISOString()

        });
    }
);

/*
======================================================
 404
======================================================
*/

app.use(
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                'Rota não encontrada.',

            path:
                req.path

        });
    }
);

/*
======================================================
 ERROS
======================================================
*/

app.use(
    (err, req, res, next) => {

        console.error(
            'Erro Express:',
            err
        );

        if (
            res.headersSent
        ) {
            return next(err);
        }

        res.status(500).json({

            success: false,

            message:
                'Erro interno do servidor.'

        });
    }
);

/*
======================================================
 SERVIDOR
======================================================
*/

server.listen(
    PORT,
    '0.0.0.0',
    () => {

        console.log(
            '======================================'
        );

        console.log(
            'Meu Discord iniciado'
        );

        console.log(
            `Porta: ${PORT}`
        );

        console.log(
            `Frontend: ${FRONTEND_URL}`
        );

        console.log(
            'Socket.IO: ativo'
        );

        console.log(
            'CORS: configurado'
        );

        console.log(
            '======================================'
        );

    }
);
