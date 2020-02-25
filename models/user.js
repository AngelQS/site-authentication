const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
const passport = require('passport');

const userSchema = new Schema(
  {
    email: String,
    username: String,
    password: String,
  },
  { timestamps: true },
);

userSchema.methods.encryptPassword = async (password) => {
  try {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  } catch (error) {
    throw new Error('Hashing failed', error);
  }
};

userSchema.methods.matchPassword = async function(password) {
  try {
    return await bcrypt.compare(password, this.password);
    console.log('bcrypt.compare:', bcrypt.compare(password, this.password));
  } catch (error) {
    throw new Error('Passwords are not equals.', error);
  }
};

module.exports = mongoose.model('user', userSchema);
