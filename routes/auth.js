require('dotenv').config();
const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const router = express.Router();
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.jwtSecret;
const multer = require('multer');
const { google } = require('googleapis');
const fs = require('fs');

const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, '/tmp/uploads');
	},
	filename: function (req, file, cb) {
		cb(null, file.fieldname + '-' + Date.now());
	},
});
const upload = multer({ storage: storage });

const User = require('../models/user');
const Trip = require('../models/trip');
const Transaction = require('../models/transaction');

router.get('/tryget', [], async (req, res) => {
	return res.json({ msg: 'get works!' });
});

router.post('/trypost', [], async (req, res) => {
	return res.json({ msg: 'post works!' });
});

router.post(
	'/signup',
	[
		body('name').notEmpty().withMessage('Name is required').trim(),
		body('email').isEmail().withMessage('Invalid email address').trim(),
		body('password')
			.notEmpty()
			.withMessage('Password is required')
			.matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/)
			.withMessage('Password must contain at least one letter, one number, and be at least 8 characters long'),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.json({ errors: errors.array(), success: false });
		}
		const salt = await bcrypt.genSalt(10);
		let secPass = await bcrypt.hash(req.body.password, salt);
		try {
			let checkIt = await User.findOne({ email: req.body.email });
			if (checkIt) {
				return res.json({ success: false, errors: [{ msg: 'You are already a user.' }] });
			}
			await User.create({
				name: req.body.name,
				email: req.body.email,
				password: secPass,
				trips: [],
				invites: [],
				upi: '',
			});
			let userData = await User.findOne({ email: req.body.email });
			const newData = {
				id: userData._id,
			};
			const newAuthToken = jwt.sign(newData, jwtSecret, { expiresIn: '30m' });
			res.json({ success: true, authToken: newAuthToken });
		} catch (error) {
			console.log(error);
			res.json({ success: false, errors: [{ msg: 'Backend Error, Contact Admin' }] });
		}
	}
);

router.post(
	'/login',
	[body('password').notEmpty().withMessage('Password is required!').trim(), body('email').isEmail().withMessage('Invalid email address!').trim()],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.json({ errors: errors.array(), success: false });
		}
		let userData = await User.findOne({ email: req.body.email });
		if (!userData) {
			return res.json({ success: false, errors: [{ msg: 'No account found with this email address!' }] });
		}
		const passwordCmp = await bcrypt.compare(req.body.password, userData.password);
		if (!passwordCmp) {
			return res.json({ success: false, errors: [{ msg: 'Password is incorrect!' }] });
		}
		const data = {
			id: userData._id,
		};
		const authToken = jwt.sign(data, jwtSecret, { expiresIn: '30m' });
		res.json({ success: true, authToken: authToken });
	}
);

router.post('/uploadDrive', upload.array('files'), async (req, res) => {
	const credentialsJson = Buffer.from(process.env.GOOGLE_CREDENTIALS_BASE64, 'base64').toString('utf-8');
	const credentials = JSON.parse(credentialsJson);
	const auth = new google.auth.GoogleAuth({
		credentials,
		scopes: 'https://www.googleapis.com/auth/drive',
	});
	// console.log(auth);
	const drive = google.drive({
		version: 'v3',
		auth,
	});
	const uploadedFiles = [];
	// console.log(req.files);
	for (let i = 0; i < req.files.length; i++) {
		// console.log(req.files[i]);
		const file = req.files[i];
		const response = await drive.files.create({
			requestBody: {
				name: file.originalname,
				mimeType: file.mimeType,
				parents: ['16quUB1EzahB5Pdu8PO4CjEaPBDYnB156'],
			},
			media: {
				body: fs.createReadStream(file.path),
			},
			fields: 'id',
		});
		drive.permissions.create({
			fileId: response.data.id,
			requestBody: {
				role: 'reader',
				type: 'anyone',
			},
		});

		uploadedFiles.push(response.data.id);
		fs.unlink(file.path, err => {
			if (err) {
				// console.error(`Failed to delete local file: ${file.path}`, err);
			} else {
				// console.log(`Successfully deleted local file: ${file.path}`);
			}
		});
	}
	res.json({ files: uploadedFiles });
});

module.exports = router;
