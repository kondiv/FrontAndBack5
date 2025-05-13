// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const users = [];

// Важно! Добавляем middlware для обработки x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

// Так же используем JSON-парсер
app.use(express.json());

// Включаем CORS для безопасности
app.use(cors());

// Генерируем секретный ключ для JWT
const secretKey = 'supersecretkey';

// Главная страница
app.get('/', (req, res) => {
    const mainPagePath = path.join(__dirname, 'main.html');
    fs.readFile(mainPagePath, 'utf8', (err, content) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }
        res.send(content); // Отправляем содержание главной страницы
    });
});

// Форма регистрации
app.get('/register', (req, res) => {
    const registrationFormPath = path.join(__dirname, 'register.html');
    fs.readFile(registrationFormPath, 'utf8', (err, content) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }
        res.send(content); // Возвращаем форму регистрации
    });
});

// Форма авторизации
app.get('/login', (req, res) => {
    const loginFormPath = path.join(__dirname, 'login.html');
    fs.readFile(loginFormPath, 'utf8', (err, content) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }
        res.send(content); // Возвращаем форму авторизации
    });
});

// Регистрация нового пользователя
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send({ message: 'Username or Password missing' });
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users.push({ id: Date.now(), username, password: hashedPassword });
        res.send({ message: 'User registered successfully!' });
    } catch(err) {
        console.error(err.message);
        res.status(500).send({ message: err.message });
    }
});

// Вход пользователя и получение JWT-токена
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) return res.status(401).send({ message: 'Invalid credentials' });

    try {
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
            res.send({ token });
        } else {
            res.status(401).send({ message: 'Invalid credentials' });
        }
    } catch(err) {
        console.error(err.message);
        res.status(500).send({ message: err.message });
    }
});

// Middleware для защиты маршрутов с проверкой JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send({ message: 'Access denied! No token provided.' });

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(403).send({ message: 'Invalid token!' });
        req.userId = decoded.id;
        next();
    });
};

// Маршрут, защищенный JWT
app.get('/protected', authenticateToken, (req, res) => {
    res.send({ message: 'Это защищенная область.', userId: req.userId });
});

// Запускаем сервер
app.listen(port, () => {
    console.log(`Сервер запущен на http://localhost:${port}`);
});