const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

passport.use(
  'local',
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: false,
    },
    async (email, password, done) => {
      console.log('password:', password);
      try {
        // Check if the email already exists
        const user = await User.findOne({ email });
        console.log('user:', user);
        if (!user) {
          return done(null, false, { message: 'User not found.' });
        }
        // Check if the password is correct
        const match = await user.matchPassword(password);

        if (!match) {
          return done(null, false, { message: 'Incorrect Password.' });
        }

        // Check if the account has been verified
        if (!user.active) {
          return done(null, false, { message: 'You must first verify the email we send you.' });
        }
        return done(null, user);
      } catch (error) {
        throw done(error, false);
      }
    },
  ),
);
