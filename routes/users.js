const express = require('express');
const router = express.Router();
const Joi = require('@hapi/joi');
const passport = require('passport');

const User = require('../models/user');

const userSchema = Joi.object().keys({
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
    .regex(/^([a-zA-Z0-9_.-]+)@([a-zA-Z0-9.]+).([a-zA-Z]{3,3})$/)
    .required()
    .messages({
      'string.email': 'Email must be a valid email.',
      'string.empty': 'Email is required.',
      'string.pattern.base': 'Email must not contain special characters.',
    }),
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .regex(/[a-zA-Z0-9]/)
    .required()
    .messages({
      'string.min': 'Username must be at least {#limit} characters long.',
      'string.max': 'Username must be at most {#limit} characters long.',
      'string.empty': 'Username is required.',
      'string.alphanum': 'Username must only contain alpha-numeric characters.',
    }),
  password: Joi.string()
    // Expresión de contraseña que requiere una letra minúscula, una letra mayúscula, un dígito, mas de 8 caracteres (editable) de longitud y sin espacios.
    //.regex(/^(?=.*\d)(?=.*[az])(?=.*[AZ])(?!.*\s).{8,}$/)
    .required()
    .messages({
      'string.pattern.base':
        'Password must consists at least minimum 8 characters, at least one uppercase letter, one lowercase letter, one number and one special character.',
      'string.empty': 'Password is required.',
    }),
  confirmationPassword: Joi.any()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Confirmation Password must be equals to Password.',
    }),
});

// Authorization middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error', 'You must be registered first.');
    res.redirect('/');
  }
};

const isNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash('error', 'You are already logged in.');
    res.redirect('/');
  } else {
    return next();
  }
};

// Routes

router
  .route('/register')

  .get(isNotAuthenticated, (req, res) => {
    res.redirect('/users/register');
  })

  .post(async (req, res, next) => {
    try {
      const result = userSchema.validate(req.body);
      if (result.error) {
        req.flash('error', result.error.details[0].message);
        res.redirect('/users/register');
      }
      // Checking if email is already taken
      const users = await User.find({
        $or: [
          { email: result.value.email },
          { username: result.value.username },
        ],
      });
      users.forEach(async (user) => {
        if (user.email == result.value.email) {
          req.flash('error', 'Email is already in use.');
          res.redirect('/users/register');
        }
        if (user.username == result.value.username) {
          req.flash('error', 'Username is already in use.');
          res.redirect('/users/register');
        }
      });

      // Save user to database
      await delete result.value.confirmationPassword; // confirmationPassword is deleted because is not in the user model
      const newUser = await new User(result.value);
      // Hash the password
      newUser.password = await newUser.encryptPassword(result.value.password);
      console.log('newUser:', newUser);
      await newUser.save();
      req.flash(
        'success',
        'You account has been registered successfully. Please check your mail to validate your account.',
      );
      res.redirect('/users/login');
    } catch (error) {
      next(error);
    }
  });

router
  .route('/login')
  .get(isNotAuthenticated, (req, res) => {
    res.render('login');
  })
  .post(
    passport.authenticate('local', {
      failureRedirect: '/users/login',
      successRedirect: '/users/dashboard',
      failureFlash: true,
    }),
  );

router.route('/dashboard').get((req, res) => {
  console.log('req.user:', req.user);
  res.render('dashboard', { username: req.user.username });
});

router.route('/logout').get(isAuthenticated, (req, res) => {
  req.logOut();
  req.flash('success', 'You are logged out.');
  res.redirect('/');
});

module.exports = router;
