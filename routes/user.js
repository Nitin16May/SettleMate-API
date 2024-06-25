require('dotenv').config();
const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const User = require('../models/user');
const Trip = require('../models/trip');
const Transaction = require('../models/transaction');

router.post('/getTripsData', [], async (req, res) => {
	const userData = await User.findById(req.body.id)
		.select('trips invites')
		.populate({ path: 'trips', select: 'name owner lastEdited dateCreated', populate: { path: 'owner', select: 'name -_id' } })
		.exec();
	// console.log(userData);
	return res.json({ success: true, data: userData.trips, invites: userData.invites.length, newAuthToken: req.body.newAuthToken });
});
router.post('/getInvites', [], async (req, res) => {
	const userData = await User.findById(req.body.id)
		.populate({ path: 'invites', select: 'name', populate: { path: 'owner', select: 'name -_id email' } })
		.exec();
	return res.json({ success: true, data: userData.invites, newAuthToken: req.body.newAuthToken });
});
router.post('/getName', [], async (req, res) => {
	const userData = await User.findById(req.body.id).exec();
	return res.json({ success: true, data: userData.name, newAuthToken: req.body.newAuthToken });
});
router.post('/getuserData', [], async (req, res) => {
	const userData = await User.findById(req.body.id).select('name email upi').exec();
	return res.json({ success: true, data: userData, newAuthToken: req.body.newAuthToken });
});
router.post('/updateprofile', [body('name').notEmpty().withMessage('Name is required').trim(), body('upi').trim()], async (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.json({ errors: errors.array(), success: false, newAuthToken: req.body.newAuthToken });
	}
	try {
		let oData = await User.findById(req.body.id);
		if (!oData) {
			return res.json({ success: false, errors: [{ msg: 'User not found' }] });
		}
		oData.name = req.body.name;
		oData.upi = req.body.upi;
		await oData.save();
		res.json({ success: true, newAuthToken: req.body.newAuthToken });
	} catch (error) {
		console.log(error);
		res.json({ success: false, errors: [{ msg: 'Backend Error, Contact Admin' }], newAuthToken: req.body.newAuthToken });
	}
});

module.exports = router;
