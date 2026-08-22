const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const server = http.createServer(app);


/* ======================================================
   CONFIGURAÇÃO
====================================================== */

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;


/* ======================================================
   CORS
====================================================== */

app.use(
    cors({
        origin: true,
        credentials: true
    })
);


/* ======================================================
   SOCKET.IO
====================================================== */

const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true,
        methods: [
            'GET',
            'POST'
        ]
    }
});


/* ======================================================
   BODY
====================================================== */

app.use(
    express.json({
        limit: '10mb'
    })
);

app.use(
    express.urlencoded({
        limit: '10mb',
        extended: true
    })
);


/* ======================================================
   ARQUIVOS ESTÁTICOS
====================================================== */

app.use(
    '/css',
    express.static(
        path.join(ROOT_DIR, 'css')
    )
);

app.use(
    '/js',
    express.static(
        path.join(ROOT_DIR, 'js')
    )
);

app.use(
    '/assets',
    express.static(
        path.join(ROOT_DIR, 'assets')
    )
);

/*
   IMPORTANTE:
   Permite que Express encontre index.html,
   login.html e outros arquivos na raiz.
*/

app.use(
    express.static(ROOT_DIR)
);


/* ======================================================
   BANCO DE DADOS
====================================================== */

const db = new sqlite3.Database(
    path.join(ROOT_DIR, 'database.db'),
    error => {

        if (error) {

            console.error(
                'Erro ao conectar SQLite:',
                error
            );

            return;
        }

        console.log(
            'Banco SQLite conectado.'
        );

    }
);


/* ======================================================
   CRIAR TABELAS
====================================================== */

db.serialize(() => {

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT ''
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT NOT NULL,
            user2 TEXT NOT NULL,
            status TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL
        )
    `);

});


/* ======================================================
   SESSÕES
====================================================== */

const sessions = new Map();


function createSession(username) {

    const token =
        crypto
            .randomBytes(32)
            .toString('hex');


    sessions.set(
        token,
        {
            username,
            createdAt: Date.now()
        }
    );


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


    return (
        sessions.get(
            match[1]
        ) || null
    );

}


function requireLogin(
    req,
    res,
    next
) {

    const session =
        getSession(req);


    if (!session) {

        return res
            .status(401)
            .json({
                success: false,
                loggedIn: false,
                message:
                    'Não autenticado.'
            });

    }


    req.username =
        session.username;


    next();

}


/* ======================================================
   STATUS
====================================================== */

app.get(
    '/api/status',
    (req, res) => {

        res.json({
            online: true,
            server: 'Meu Discord',
            time:
                new Date()
                    .toISOString()
        });

    }
);


/* ======================================================
   LOGIN.HTML
====================================================== */

app.get(
    '/login.html',
    (req, res) => {

        const session =
            getSession(req);


        if (session) {

            return res.redirect(
                '/index.html'
            );

        }


        res.sendFile(
            path.join(
                ROOT_DIR,
                'login.html'
            )
        );

    }
);


/* ======================================================
   CADASTRO
====================================================== */

app.post(
    '/register',
    async (req, res) => {

        const username =
            String(
                req.body.username || ''
            ).trim();

        const password =
            String(
                req.body.password || ''
            );


        if (
            !username ||
            !password
        ) {

            return res
                .status(400)
                .send(
                    'Preencha todos os campos.'
                );

        }


        if (
            username.length < 3
        ) {

            return res
                .status(400)
                .send(
                    'O usuário precisa ter pelo menos 3 caracteres.'
                );

        }


        if (
            password.length < 4
        ) {

            return res
                .status(400)
                .send(
                    'A senha precisa ter pelo menos 4 caracteres.'
                );

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
                (
                    username,
                    password,
                    avatar
                )
                VALUES (?, ?, '')
                `,
                [
                    username,
                    hashedPassword
                ],
                function(error) {

                    if (error) {

                        console.error(
                            'Erro cadastro:',
                            error
                        );


                        if (
                            error.message &&
                            error.message.includes(
                                'UNIQUE'
                            )
                        ) {

                            return res
                                .status(400)
                                .send(
                                    'Usuário já existe!'
                                );

                        }


                        return res
                            .status(500)
                            .send(
                                'Erro ao criar conta.'
                            );

                    }


                    res.send(
                        'Conta criada com sucesso!'
                    );

                }
            );

        } catch (error) {

            console.error(
                error
            );


            res
                .status(500)
                .send(
                    'Erro no servidor.'
                );

        }

    }
);


/* ======================================================
   LOGIN
====================================================== */

app.post(
    '/login',
    (req, res) => {

        const username =
            String(
                req.body.username || ''
            ).trim();

        const password =
            String(
                req.body.password || ''
            );


        if (
            !username ||
            !password
        ) {

            return res
                .status(400)
                .send(
                    'Preencha usuário e senha.'
                );

        }


        db.get(
            `
            SELECT *
            FROM users
            WHERE username = ?
            `,
            [
                username
            ],
            async (
                error,
                user
            ) => {

                if (error) {

                    console.error(
                        'Erro login:',
                        error
                    );


                    return res
                        .status(500)
                        .send(
                            'Erro no servidor.'
                        );

                }


                if (!user) {

                    return res
                        .status(401)
                        .send(
                            'Usuário ou senha incorretos!'
                        );

                }


                try {

                    const correct =
                        await bcrypt.compare(
                            password,
                            user.password
                        );


                    if (!correct) {

                        return res
                            .status(401)
                            .send(
                                'Usuário ou senha incorretos!'
                            );

                    }


                    const token =
                        createSession(
                            user.username
                        );


                    res.setHeader(
                        'Set-Cookie',
                        `chat_session=${token}; HttpOnly; Path=/; SameSite=None; Secure`
                    );


                    res.json({
                        success: true,
                        username:
                            user.username
                    });

                } catch (error) {

                    console.error(
                        error
                    );


                    res
                        .status(500)
                        .send(
                            'Erro no servidor.'
                        );

                }

            }
        );

    }
);


/* ======================================================
   ME
====================================================== */

app.get(
    '/me',
    (req, res) => {

        const session =
            getSession(req);


        if (!session) {

            return res
                .status(401)
                .json({
                    loggedIn: false
                });

        }


        res.json({
            loggedIn: true,
            username:
                session.username
        });

    }
);


/* ======================================================
   LOGOUT
====================================================== */

app.post(
    '/logout',
    (req, res) => {

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
            'chat_session=; HttpOnly; Path=/; Max-Age=0; SameSite=None; Secure'
        );


        res.json({
            success: true
        });

    }
);


/* ======================================================
   PÁGINA PRINCIPAL
====================================================== */

app.get(
    '/',
    (req, res) => {

        const session =
            getSession(req);


        if (!session) {

            return res.sendFile(
                path.join(
                    ROOT_DIR,
                    'login.html'
                )
            );

        }


        res.sendFile(
            path.join(
                ROOT_DIR,
                'index.html'
            )
        );

    }
);


app.get(
    '/index.html',
    (req, res) => {

        const session =
            getSession(req);


        if (!session) {

            return res.sendFile(
                path.join(
                    ROOT_DIR,
                    'login.html'
                )
            );

        }


        res.sendFile(
            path.join(
                ROOT_DIR,
                'index.html'
            )
        );

    }
);


/* ======================================================
   AVATAR
====================================================== */

app.post(
    '/update-avatar',
    requireLogin,
    (req, res) => {

        const username =
            req.username;

        const avatar =
            req.body.avatar || '';


        if (!avatar) {

            return res
                .status(400)
                .send(
                    'Nenhuma imagem enviada.'
                );

        }


        if (
            typeof avatar !== 'string'
        ) {

            return res
                .status(400)
                .send(
                    'Avatar inválido.'
                );

        }


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
            function(error) {

                if (error) {

                    console.error(
                        'Erro avatar:',
                        error
                    );


                    return res
                        .status(500)
                        .send(
                            'Erro ao atualizar avatar.'
                        );

                }


                res.json({
                    success: true,
                    message:
                        'Avatar atualizado com sucesso!'
                });

            }
        );

    }
);


/* ======================================================
   USUÁRIO
====================================================== */

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
            [
                username
            ],
            (
                error,
                user
            ) => {

                if (
                    error ||
                    !user
                ) {

                    return res.json({
                        username,
                        avatar: ''
                    });

                }


                res.json(
                    user
                );

            }
        );

    }
);


/* ======================================================
   AMIGOS
====================================================== */

app.get(
    '/friends/:username',
    requireLogin,
    (req, res) => {

        const username =
            req.params.username;


        if (
            username !==
            req.username
        ) {

            return res
                .status(403)
                .json({
                    error:
                        'Acesso negado.'
                });

        }


        db.all(
            `
            SELECT *
            FROM friendships
            WHERE
                user1 = ?
                OR user2 = ?
            `,
            [
                username,
                username
            ],
            (
                error,
                rows
            ) => {

                if (error) {

                    console.error(
                        error
                    );


                    return res
                        .status(500)
                        .send(
                            'Erro ao buscar amigos'
                        );

                }


                const friends = [];
                const pending = [];


                rows.forEach(
                    row => {

                        if (
                            row.status ===
                            'accepted'
                        ) {

                            friends.push(
                                row.user1 === username
                                    ? row.user2
                                    : row.user1
                            );

                        }


                        if (
                            row.status ===
                                'pending' &&
                            row.user2 ===
                                username
                        ) {

                            pending.push(
                                row.user1
                            );

                        }

                    }
                );


                const details =
                    (
                        names,
                        callback
                    ) => {

                        if (
                            names.length === 0
                        ) {

                            return callback(
                                []
                            );

                        }


                        const placeholders =
                            names
                                .map(
                                    () => '?'
                                )
                                .join(',');


                        db.all(
                            `
                            SELECT username, avatar
                            FROM users
                            WHERE username IN (${placeholders})
                            `,
                            names,
                            (
                                error,
                                result
                            ) => {

                                callback(
                                    result || []
                                );

                            }
                        );

                    };


                details(
                    friends,
                    friendData => {

                        details(
                            pending,
                            pendingData => {

                                res.json({
                                    friends:
                                        friendData,
                                    pendingRequests:
                                        pendingData
                                });

                            }
                        );

                    }
                );

            }
        );

    }
);


/* ======================================================
   ADICIONAR AMIGO
====================================================== */

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

            return res
                .status(400)
                .send(
                    'Digite um usuário.'
                );

        }


        if (
            username ===
            friendName
        ) {

            return res
                .status(400)
                .send(
                    'Você não pode se adicionar.'
                );

        }


        db.get(
            `
            SELECT *
            FROM users
            WHERE username = ?
            `,
            [
                friendName
            ],
            (
                error,
                user
            ) => {

                if (error) {

                    console.error(
                        error
                    );


                    return res
                        .status(500)
                        .send(
                            'Erro no servidor.'
                        );

                }


                if (!user) {

                    return res
                        .status(404)
                        .send(
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
                    (
                        error,
                        existing
                    ) => {

                        if (error) {

                            return res
                                .status(500)
                                .send(
                                    'Erro no servidor.'
                                );

                        }


                        if (existing) {

                            if (
                                existing.status ===
                                'accepted'
                            ) {

                                return res
                                    .status(400)
                                    .send(
                                        'Vocês já são amigos.'
                                    );

                            }


                            return res
                                .status(400)
                                .send(
                                    'Já existe um pedido pendente entre vocês.'
                                );

                        }


                        db.run(
                            `
                            INSERT INTO friendships
                            (
                                user1,
                                user2,
                                status
                            )
                            VALUES (?, ?, 'pending')
                            `,
                            [
                                username,
                                friendName
                            ],
                            error => {

                                if (error) {

                                    console.error(
                                        error
                                    );


                                    return res
                                        .status(500)
                                        .send(
                                            'Erro ao enviar pedido.'
                                        );

                                }


                                io.to(
                                    friendName
                                ).emit(
                                    'refresh friends'
                                );


                                res.send(
                                    'Pedido de amizade enviado!'
                                );

                            }
                        );

                    }
                );

            }
        );

    }
);


/* ======================================================
   ACEITAR AMIGO
====================================================== */

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
            function(error) {

                if (error) {

                    return res
                        .status(500)
                        .send(
                            'Erro ao aceitar pedido.'
                        );

                }


                if (
                    this.changes === 0
                ) {

                    return res
                        .status(400)
                        .send(
                            'Pedido não encontrado.'
                        );

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


                res.send(
                    'Pedido aceito!'
                );

            }
        );

    }
);


/* ======================================================
   REMOVER AMIGO
====================================================== */

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
            error => {

                if (error) {

                    return res
                        .status(500)
                        .send(
                            'Erro ao remover amizade.'
                        );

                }


                io.to(
                    friendName
                ).emit(
                    'refresh friends'
                );


                res.send(
                    'Amizade removida.'
                );

            }
        );

    }
);


/* ======================================================
   SOCKET.IO
====================================================== */

const activeUsers = {};


io.on(
    'connection',
    socket => {

        socket.callRoom = null;
        socket.username = null;


        /* ==================================================
           REGISTRAR USUÁRIO
        ================================================== */

        socket.on(
            'register user',
            username => {

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
                    'Socket conectado:',
                    username
                );

            }
        );


        /* ==================================================
           ATUALIZAR AMIGOS
        ================================================== */

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


        /* ==================================================
           FECHAR CHAT
        ================================================== */

        socket.on(
            'force close chat',
            data => {

                if (
                    !data ||
                    !data.targetUser
                ) {
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


        /* ==================================================
           ENTRAR NA SALA
        ================================================== */

        socket.on(
            'join room',
            room => {

                if (!room) {
                    return;
                }


                [
                    ...socket.rooms
                ].forEach(
                    r => {

                        if (
                            r !== socket.id &&
                            r !== socket.username
                        ) {

                            socket.leave(
                                r
                            );

                        }

                    }
                );


                socket.join(
                    room
                );


                const parts =
                    room.includes('_')
                        ? room.split('_')
                        : room.split('-');


                if (
                    parts.length < 2
                ) {

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
                    async (
                        error,
                        rows
                    ) => {

                        if (
                            error ||
                            !rows
                        ) {

                            return;
                        }


                        const messages = [];


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
                                        [
                                            msg.sender
                                        ],
                                        (
                                            error,
                                            user
                                        ) => {

                                            messages.push({
                                                ...msg,
                                                avatar:
                                                    user
                                                        ? user.avatar
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
                            messages
                        );

                    }
                );

            }
        );


        /* ==================================================
           MENSAGEM PRIVADA
        ================================================== */

        socket.on(
            'private message',
            data => {

                if (!data) {
                    return;
                }


                if (
                    !data.sender ||
                    !data.receiver ||
                    !data.message ||
                    !data.room
                ) {

                    return;
                }


                if (
                    socket.username &&
                    data.sender !==
                        socket.username
                ) {

                    return;
                }


                db.get(
                    `
                    SELECT avatar
                    FROM users
                    WHERE username = ?
                    `,
                    [
                        data.sender
                    ],
                    (
                        error,
                        user
                    ) => {

                        const avatar =
                            user
                                ? user.avatar
                                : '';


                        db.run(
                            `
                            INSERT INTO private_messages
                            (
                                sender,
                                receiver,
                                message
                            )
                            VALUES (?, ?, ?)
                            `,
                            [
                                data.sender,
                                data.receiver,
                                data.message
                            ],
                            error => {

                                if (error) {

                                    console.error(
                                        error
                                    );

                                    return;
                                }


                                const message = {
                                    ...data,
                                    avatar
                                };


                                io.to(
                                    data.room
                                ).emit(
                                    'private message',
                                    message
                                );


                                const sockets =
                                    io
                                        .sockets
                                        .adapter
                                        .rooms
                                        .get(
                                            data.receiver
                                        );


                                if (
                                    sockets
                                ) {

                                    for (
                                        const socketId
                                        of sockets
                                    ) {

                                        const receiver =
                                            io
                                                .sockets
                                                .sockets
                                                .get(
                                                    socketId
                                                );


                                        if (
                                            receiver &&
                                            !receiver.rooms.has(
                                                data.room
                                            )
                                        ) {

                                            receiver.emit(
                                                'private message',
                                                message
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


        /* ==================================================
           CHAMADA
        ================================================== */

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


        /* ==================================================
           RENEGOCIAÇÃO
        ================================================== */

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


        /* ==================================================
           ICE
        ================================================== */

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


        /* ==================================================
           DESLIGAR
        ================================================== */

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


        /* ==================================================
           TELA PAROU
        ================================================== */

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


        /* ==================================================
           DESCONECTAR
        ================================================== */

        socket.on(
            'disconnect',
            () => {

                const username =
                    activeUsers[
                        socket.id
                    ];


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


                console.log(
                    'Socket desconectado:',
                    username ||
                    socket.id
                );

            }
        );

    }
);


/* ======================================================
   ERROS DO SERVIDOR
====================================================== */

process.on(
    'uncaughtException',
    error => {

        console.error(
            'Erro não tratado:',
            error
        );

    }
);


process.on(
    'unhandledRejection',
    error => {

        console.error(
            'Promise rejeitada:',
            error
        );

    }
);


/* ======================================================
   INICIAR SERVIDOR
====================================================== */

server.listen(
    PORT,
    '0.0.0.0',
    () => {

        console.log(
            `Servidor Meu Discord rodando na porta ${PORT}`
        );

    }
);
