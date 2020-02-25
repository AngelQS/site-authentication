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
        console.log('match:', match);
        if (match) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect Password.' });
        }
      } catch (error) {
        throw done(error, false);
      }
    },
  ),
);
