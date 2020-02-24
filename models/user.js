const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const userSchema = new Schema(
  {
    email: String,
    username: String,
    password: String,
  },
  { timestamps: true },
);

module.exports.User = mongoose.model('user', userSchema);

module.exports.hashPassword = async (password) => {
  try {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    throw new error('Hashing failed', error);
  }
};
