require('dotenv').config();
const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const {
	Types: { ObjectId },
} = require('mongoose');
const { PriorityQueue } = require('@datastructures-js/priority-queue');

const User = require('../models/user');
const Trip = require('../models/trip');
const Chat = require('../models/chat');
const Transaction = require('../models/transaction');

router.post('/createtrip', [body('name').notEmpty().withMessage('Name cannot be Empty')], async (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.json({
			errors: errors.array(),
			success: false,
			newAuthToken: req.body.newAuthToken,
		});
	}
	const newTripChat = new Chat({
		chat: [],
	});
	newTripChat
		.save()
		.then(chatId => {
			const trip = new Trip({
				name: req.body.name,
				owner: req.body.id,
				lastEdited: new Date(),
				dateCreated: new Date(),
				members: [req.body.id],
				transactions: [],
				transfers: [],
				transfersUpdated: false,
				chat: chatId,
			});
			trip.save()
				.then(result => {
					User.findById(req.body.id)
						.then(userDoc => {
							userDoc.addTrip(result._id).then(() => {
								return res.json({
									tripid: result._id,
									success: true,
									newAuthToken: req.body.newAuthToken,
								});
							});
						})
						.catch(err => {
							console.log(err);
						});
				})
				.catch(err => {
					console.log(err);
				});
		})
		.catch(err => {
			console.log(err);
		});
});

router.post('/createtransaction', [body('name').notEmpty().withMessage('Name cannot be Empty')], async (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.json({
			errors: errors.array(),
			success: false,
			newAuthToken: req.body.newAuthToken,
		});
	}
	const transaction = new Transaction({
		name: req.body.name,
		desc: '',
		owner: req.body.id,
		inTrip: req.body.tripid,
		bill: '',
		amt: 0,
		lastEdited: new Date(),
		dateCreated: new Date(),
		distributedAmong: [],
	});
	transaction
		.save()
		.then(result => {
			Trip.findById(req.body.tripid)
				.then(tripDoc => {
					tripDoc.addTransaction(result._id).then(() => {
						return res.json({
							transactionid: result._id,
							success: true,
							newAuthToken: req.body.newAuthToken,
						});
					});
				})
				.catch(err => {
					console.log(err);
				});
		})
		.catch(err => {
			console.log(err);
		});
});

router.post('/getTripData', [], async (req, res) => {
	// console.log('/getTripData');
	const trip = await Trip.findById(req.body.tripid).select('name owner chat').populate({ path: 'owner', select: 'name' }).exec();
	const tripChat = await Chat.findById(trip.chat);
	// console.log(trip);
	const tripp = await Trip.findById(req.body.tripid).select('members').populate({ path: 'members', select: 'name' }).exec();
	const memberMap = {};
	// console.log(tripp);
	tripp.members.forEach(member => {
		memberMap[member._id] = member.name;
	});

	res.json({
		data: trip,
		chat: tripChat.chat,
		mapId2Name: memberMap,
		userId: req.body.id,
		success: true,
		newAuthToken: req.body.newAuthToken,
	});
});

router.post('/getMinTripData', [], async (req, res) => {
	// console.log('/getTripData');
	const trip = await Trip.findById(req.body.tripid).select('name owner').exec();
	res.json({
		data: trip,
		userId: req.body.id,
		success: true,
		newAuthToken: req.body.newAuthToken,
	});
});

router.post('/getTripMembers', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid)
		.select('members')
		.populate({
			path: 'members',
			select: 'name email',
		})
		.exec();
	res.json({
		data: trip,
		myID: req.body.id,
		success: true,
		newAuthToken: req.body.newAuthToken,
	});
});
router.post('/getTripTransactions', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid)
		.select('transactions')
		.populate({
			path: 'transactions',
			select: 'name amt owner lastEdited dateCreated currentStatus',
			populate: {
				path: 'owner',
				select: 'name',
			},
		})
		.exec();
	res.json({
		data: trip,
		success: true,
		newAuthToken: req.body.newAuthToken,
	});
});

router.post('/addChat', [], async (req, res) => {
	// console.log('hits');
	const trip = await Trip.findById(req.body.tripid);
	const tripChat = await Chat.findById(trip.chat);
	// console.log(req.body.msg);
	const temp = ObjectId.createFromHexString(req.body.msg.from);
	req.body.msg.from = temp;
	tripChat.chat.push(req.body.msg);
	tripChat.save().then(() => {
		return res.json({ success: true, newAuthToken: req.body.newAuthToken });
	});
});

router.post('/clearChat', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const tripChat = await Chat.findById(trip.chat);
	// console.log(trip.owner,ObjectId.createFromHexString(req.body.id));
	// console.log(trip.owner.equals(req.body.id));
	if (trip.owner.equals(req.body.id)) {
		tripChat.chat = [];
		tripChat.save().then(() => {
			return res.json({
				success: true,
				newAuthToken: req.body.newAuthToken,
			});
		});
	} else
		return res.json({
			success: false,
			newAuthToken: req.body.newAuthToken,
			errors: [{ msg: 'Only admin can clear chat!' }],
		});
});

router.post('/invite', [body('email').isEmail().withMessage('Enter Valid Email')], async (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.json({
			errors: errors.array(),
			success: false,
			newAuthToken: req.body.newAuthToken,
		});
	}
	const user = await User.findOne({ email: req.body.email });
	if (user) {
		user.addInvite(req.body.tripid).then(() => {
			return res.json({
				success: true,
				newAuthToken: req.body.newAuthToken,
				errors: [{ msg: `Invite sent to ${user.name}` }],
			});
		});
	} else {
		return res.json({
			success: false,
			newAuthToken: req.body.newAuthToken,
			errors: [{ msg: 'User does not exist!' }],
		});
	}
});
router.post('/acceptInvite', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const user = await User.findById(req.body.id);
	// console.log(req.body.tripid);
	// console.log(req.body.id);
	await trip.addMember(req.body.id);
	await user.removeInvite(req.body.tripid);
	await user.addTrip(req.body.tripid);
	return res.json({ success: true, newAuthToken: req.body.newAuthToken });
});
router.post('/rejectInvite', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const user = await User.findById(req.body.id);
	// console.log(req.body.tripid);
	// console.log(req.body.id);
	await user.removeInvite(req.body.tripid);
	return res.json({ success: true, newAuthToken: req.body.newAuthToken });
});

router.post('/getTripTransfers', [], async (req, res, next) => {
	const trip = await Trip.findById(req.body.tripid).select('transfersUpdated transfers transactions').populate('transactions');
	// console.log(trip);
	// console.log(trip.transfersUpdated);
	// if (trip.transfersUpdated) {
	// 	next();
	// 	return;
	// }
	const net = new Map();
	// console.log(trip.transactions);
	for (let i in trip.transactions) {
		if (trip.transactions[i].currentStatus === 'Enabled') {
			let a = net.get(trip.transactions[i].owner.toString()) || 0;
			net.set(trip.transactions[i].owner.toString(), a - trip.transactions[i].amt);
			for (let j in trip.transactions[i].distributedAmong) {
				a = net.get(trip.transactions[i].distributedAmong[j].person.toString()) || 0;
				net.set(trip.transactions[i].distributedAmong[j].person.toString(), a + trip.transactions[i].distributedAmong[j].amt);
			}
		}
	}
	// console.log(net);
	const senders = new PriorityQueue((a, b) => {
		if (a.amt < b.amt) return 1;
		return -1;
	});
	const receivers = new PriorityQueue((a, b) => {
		if (a.amt < b.amt) return 1;
		return -1;
	});
	net.forEach(function (value, key) {
		if (value < 0) receivers.enqueue({ amt: value * -1, who: key });
		if (value > 0) senders.enqueue({ amt: value, who: key });
	});
	console.log(receivers);
	console.log(senders);
	trip.transfers = [];
	while (!senders.isEmpty()) {
		let s = senders.dequeue();
		let r = receivers.dequeue();
		let sd = s.who;
		let rd = r.who;
		let sa = s.amt;
		let ra = r.amt;
		// console.log(sd + ' ' + sa);
		// console.log(rd + ' ' + ra);
		if (ra === sa) {
			trip.transfers.push({ from: sd, amt: sa, to: rd });
			// console.log(sd, sa, rd);
		} else if (ra > sa) {
			trip.transfers.push({ from: sd, amt: sa, to: rd });
			// console.log(sd, sa, rd);
			receivers.enqueue({ amt: ra - sa, who: rd });
		} else {
			trip.transfers.push({ from: sd, amt: ra, to: rd });
			// console.log(sd, ra, rd);
			senders.enqueue({ amt: sa - ra, who: sd });
		}
	}
	trip.transfersUpdated = true;
	trip.save().then(() => next());
});
router.post('/getTripTransfers', [], async (req, res) => {
	// console.log('hits');
	const trip = await Trip.findById(req.body.tripid)
		.select('transfers members')
		.populate({
			path: 'transfers.from transfers.to',
			select: 'name email upi',
		})
		.exec();
	let notintrip = true;
	for (let i in trip.members) {
		if (trip.members[i]._id.toString() === req.body.id.toString()) notintrip = false;
	}
	return res.json({
		success: true,
		newAuthToken: req.body.newAuthToken,
		data: trip.transfers,
		notintrip: notintrip,
	});
});

router.post('/updateTripName', [body('name').notEmpty().withMessage('Name cannot be Empty')], async (req, res) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.json({
			errors: errors.array(),
			success: false,
			newAuthToken: req.body.newAuthToken,
		});
	}
	const trip = await Trip.findById(req.body.tripid);
	trip.name = req.body.name;
	trip.save().then(() => {
		return res.json({
			success: true,
			newAuthToken: req.body.newAuthToken,
		});
	});
});

router.post('/kickMember', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const user = await User.findById(req.body.userid);
	// console.log(trip.owner.toString() === req.body.id.toString());
	if (trip.owner.toString() !== req.body.id.toString())
		return res.json({
			success: false,
			newAuthToken: req.body.newAuthToken,
			errors: [{ msg: 'Only Admin can Kick Members' }],
		});
	let temp = trip.members.filter(item => item.toString() !== req.body.userid.toString());
	// console.log(temp);
	trip.members = temp;
	trip.save().then(() => {
		temp = user.trips.filter(item => item.toString() !== req.body.tripid.toString());
		user.trips = temp;
		user.save().then(() => {
			return res.json({
				success: true,
				newAuthToken: req.body.newAuthToken,
			});
		});
	});
});

router.post('/adminMember', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const user = await User.findById(req.body.userid);
	let notintrip = true;
	for (let i in trip.members) {
		if (trip.members[i].toString() === user._id.toString()) notintrip = false;
	}
	if (notintrip)
		return res.json({
			success: false,
			newAuthToken: req.body.newAuthToken,
			errors: [{ msg: 'User is not a member!' }],
		});
	trip.owner = user._id;
	trip.save().then(() => {
		return res.json({
			success: true,
			newAuthToken: req.body.newAuthToken,
		});
	});
});

router.post('/getTransactionData', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid).populate({ path: 'members', select: 'name email' });
	const transaction = await Transaction.findById(req.body.transactionid).populate({ path: 'owner', select: 'name email' });
	// console.log(transaction);
	let memlist = [];
	let memmap = {};
	for (let i in trip.members) {
		memlist.push(trip.members[i]._id);
		memmap[trip.members[i]._id] = trip.members[i];
	}
	let damg = [];
	let damgmap = {};
	for (let i in transaction.distributedAmong) {
		damg.push(transaction.distributedAmong[i].person);
		damgmap[transaction.distributedAmong[i].person] = transaction.distributedAmong[i].amt;
	}
	return res.json({
		success: true,
		newAuthToken: req.body.newAuthToken,
		name: transaction.name,
		desc: transaction.desc,
		amt: transaction.amt,
		damg: damg,
		damgmap: damgmap,
		members: memlist,
		memmap: memmap,
		bill: transaction.bill,
		owner: transaction.owner,
		myId: req.body.id,
		tripOwner: trip.owner,
		switchVal: transaction.currentStatus === 'Enabled',
	});
});
router.post('/updateTransaction', [], async (req, res) => {
	const trip = await Trip.findById(req.body.tripid);
	const transaction = await Transaction.findById(req.body.transactionid);

	transaction.bill = req.body.data.bill;
	transaction.currentStatus = req.body.data.currentStatus;
	transaction.amt = req.body.data.amt;
	transaction.name = req.body.data.name;
	transaction.desc = req.body.data.desc;
	transaction.lastEdited = new Date();
	transaction.distributedAmong = req.body.data.distributedAmong;
	await transaction.save();
	trip.lastEdited = new Date();
	trip.transfersUpdated = false;
	await trip.save();
	res.json({ success: true, message: 'Transaction updated successfully' });
});

module.exports = router;
