const mongoose = require('mongoose');

const { Schema } = mongoose;

const userSchema = new Schema({
	name: {
		type: String,
	},
	email: {
		type: String,
		required: true,
	},
	password: {
		type: String,
		required: true,
	},
	upi: {
		type: String,
	},
	trips: [
		{
			type: Schema.Types.ObjectId,
			ref: 'Trip',
		},
	],
	invites: [
		{
			type: Schema.Types.ObjectId,
			ref: 'Trip',
		},
	],
});

userSchema.methods.addTrip = function (tripTBA) {
	const tripIndex = this.trips.findIndex(x => {
		return tripTBA.toString() === x.toString();
	});
	if (tripIndex == -1) {
		this.trips.push(tripTBA);
	}
	return this.save();
};
userSchema.methods.addInvite = function (tripTBA) {
	const tripIndex = this.invites.findIndex(x => {
		return tripTBA.toString() === x.toString();
	});
	if (tripIndex == -1) {
		this.invites.push(tripTBA);
	}
	return this.save();
};
userSchema.methods.removeInvite = function (tripTBR) {
	this.invites = this.invites.filter(tripId => tripId.toString() !== tripTBR.toString());
	return this.save();
};
module.exports = mongoose.model('User', userSchema);
