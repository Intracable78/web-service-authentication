const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    login: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['ROLE_USER', 'ROLE_ADMIN'] },
    status: { type: String, required: true, enum: ['open', 'closed'] },
    created_at: { type: Date, default: Date.now }
  });
  
  const User = mongoose.model('User', userSchema)
  ;module.exports = User;