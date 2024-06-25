const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const tripSchema = new Schema({
	name: {
		type: String,
		required: true,
	},
	owner: {
		type: Schema.Types.ObjectId,
		ref: 'User',
		required: true,
	},
	lastEdited: {
		type: Date,
		required: true,
	},
	dateCreated: {
		type: Date,
		required: true,
	},
	members: [
		{
			type: Schema.Types.ObjectId,
			ref: 'User',
		},
	],
	transactions: [
		{
			type: Schema.Types.ObjectId,
			ref: 'Transaction',
		},
	],
	transfers: [
		{
			from: {
				type: Schema.Types.ObjectId,
				ref: 'User',
			},
			to: {
				type: Schema.Types.ObjectId,
				ref: 'User',
			},
			amt: {
				type: Number,
			},
		},
	],
	transfersUpdated: {
		type: Boolean,
		default: false,
	},
	chat: {
		type: Schema.Types.ObjectId,
		ref: 'Chat',
	},
});
tripSchema.methods.addTransaction = function (transactionTBA) {
	this.transactions.push(transactionTBA);
	this.lastEdited = new Date();
	this.transfersUpdated = false;
	return this.save();
};
tripSchema.methods.addMember = function (memberTBA) {
	this.members.push(memberTBA);
	this.lastEdited = new Date();
	return this.save();
};
module.exports = mongoose.model('Trip', tripSchema);
