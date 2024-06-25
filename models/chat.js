const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const chatSchema = new Schema({
	chat: [
		{
			msg: {
				type: String,
			},
			isImage: {
				type: Boolean,
			},
			from: {
				type: Schema.Types.ObjectId,
				ref: 'User',
			},
			date: {
				type: Date,
			},
		},
	],
});
module.exports = mongoose.model('Chat', chatSchema);
