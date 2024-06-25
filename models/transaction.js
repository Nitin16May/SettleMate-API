const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const transactionSchema = new Schema({
	owner: {
		type: Schema.Types.ObjectId,
		ref: 'User',
		required: true,
	},
	inTrip: {
		type: Schema.Types.ObjectId,
		ref: 'Trip',
		required: true,
	},
	bill: {
		type: String,
	},
	currentStatus: {
		type: String,
		enum: ['Enabled', 'Disabled'],
		default: 'Enabled',
		required: true,
	},
	amt: {
		type: Number,
		required: true,
	},
	name: {
		type: String,
		required: true,
	},
	desc: {
		type: String,
	},
	lastEdited: {
		type: Date,
		required: true,
	},
	dateCreated: {
		type: Date,
		required: true,
	},
	distributedAmong: [
		{
			person: {
				type: Schema.Types.ObjectId,
				ref: 'User',
			},
			amt: {
				type: Number,
			},
		},
	],
});
transactionSchema.methods.update = function (x) {
	this.lastEdited = new Date();
	this.name = x.name;
	this.amt = x.amt;
	this.distributedAmong = x.membersTBA;
	this.currentStatus = x.currentStatus;
	return this.save();
};
transactionSchema.methods.setstatus = function (x) {
	this.lastEdited = new Date();
	this.currentStatus = x;
	return this.save();
};

module.exports = mongoose.model('Transaction', transactionSchema);
