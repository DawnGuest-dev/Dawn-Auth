require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

const app = express();
app.use(express.json());

// PostgreSQL 설정
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
});

// JWT 옵션 설정
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
};

// JWT 전략 설정
passport.use(new JwtStrategy(jwtOptions, (jwtPayload, done) => {
    pool.query('SELECT * FROM users WHERE id = $1', [jwtPayload.id], (err, res) => {
        if (err) return done(err, false);
        if (res.rows.length > 0) {
            return done(null, res.rows[0]);
        } else {
            return done(null, false);
        }
    });
}));

app.use(passport.initialize());

// 유저 회원가입
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    pool.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
        [username, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Error creating user' });
            }
            const user = result.rows[0];
            res.status(201).json({ message: 'User created successfully', user });
        });
});

// 유저 로그인 및 JWT 발급
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    pool.query('SELECT * FROM users WHERE username = $1', [username], async (err, result) => {
        if (err || result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        // 리프레시 토큰을 DB에 저장
        pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id], (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error storing refresh token' });
            }

            res.json({
                message: 'Login successful',
                accessToken,
                refreshToken
            });
        });
    });
});

app.post('/token', (req, res) => {
    const { refreshToken } = req.body;

    if (refreshToken == null) return res.sendStatus(401);

    // DB에서 리프레시 토큰 확인
    pool.query('SELECT * FROM users WHERE refresh_token = $1', [refreshToken], (err, result) => {
        if (err || result.rows.length === 0) return res.sendStatus(403); // 유효하지 않음

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);

            const accessToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ accessToken });
        });
    });
});

app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;

    // 리프레시 토큰을 DB에서 제거
    pool.query('UPDATE users SET refresh_token = NULL WHERE refresh_token = $1', [refreshToken], (err) => {
        if (err) return res.sendStatus(500);
        res.sendStatus(204);
    });
});


// 보호된 라우트 (JWT 인증 필요)
app.get('/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'Welcome to your profile!', user: req.user });
});

// 서버 시작
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
