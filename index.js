require('dotenv').config();
const express = require('express');
const app = express();
const port = 5000;
const cors = require('cors');
app.use(cors());

const mongoose = require('mongoose');
mongoose
	.connect(process.env.MongoDB_URI)
	.then(() => console.log('Database connected successfully'))
	.catch(err => console.error('Database connection error:', err));

app.get('/', (req, res) => {
	res.send('Hello! This is an API endpoint for my personal project, SettleMate.');
});

app.use(express.json());
app.use('/', require('./routes/auth'));
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.jwtSecret;
const authMiddleware = (req, res, next) => {
	var userId;
	try {
		// console.log(process.env.jwtSecret);
		// console.log(req.body);
		userId = jwt.verify(req.body.token, jwtSecret);
	} catch (error) {
		return res.json({ success: false, logout: true, errors: [{ msg: 'Sesson Expired, Login again' }] });
	}
	req.body.id = userId.id;
	const authToken = jwt.sign({ id: userId.id }, jwtSecret, { expiresIn: '30m' });
	req.body.newAuthToken = authToken;
	next();
};
app.use('/', authMiddleware, require('./routes/user'));
app.use('/', authMiddleware, require('./routes/trip'));

const server = app.listen(port, () => {
	console.log(`Example app listening on port ${port}`);
});

const io = require('socket.io')(server, {
	cors: {
		origin: '*',
	},
});

io.on('connection', socket => {
	// console.log('A user connected');
	socket.on('joinRoom', room => {
		socket.join(room);
		// console.log(`User joined room: ${room}`);
		// socket.to(room).emit('userJoined', `A new user has joined the room: ${room}`);
	});

	socket.on('msg', ({ message, roomId }) => {
		io.to(roomId).emit('bcast', message);
	});

	socket.on('disconnect', () => {
		// console.log('User disconnected');
	});
});
