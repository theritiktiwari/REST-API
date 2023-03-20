const mongoose = require('mongoose');
const { Schema } = mongoose;
const { v4: uuidv4 } = require('uuid');

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    role: {
        type: String,
        default: "user"
    },
    verificationCode: {
        type: String,
        default: uuidv4()
    },
    verified: {
        type: Boolean,
        default: false
    },
    passwordResetCode: {
        type: String,
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('user', userSchema);
module.exports = User;