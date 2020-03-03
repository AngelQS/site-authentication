const express = require('express');
const router = express.Router();
const Joi = require('@hapi/joi');
const passport = require('passport');
const randomString = require('randomstring');

const User = require('../models/user');
const mailer = require('../misc/mailer');

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
    res.render('register');
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

      // Generate secret token
      const secretToken = randomString.generate();
      newUser.secretToken = secretToken;

      // Flag the account as inactive
      newUser.active = false;

      await newUser.save();

      // Compose an email
      const html = `<!DOCTYPE html>
      <html style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
      <head>
      <meta name="viewport" content="width=device-width" />
      <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
      <title>Actionable emails e.g. reset password</title>
          
          
      <style type="text/css">
      img {
      max-width: 100%;
      }
      body {
      -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: none; width: 100% !important; height: 100%; line-height: 1.      6em;
      }
      body {
      background-color: #f6f6f6;
      }
      @media only screen and (max-width: 640px) {
        body {
          padding: 0 !important;
        }
        h1 {
          font-weight: 800 !important; margin: 20px 0 5px !important;
        }
        h2 {
          font-weight: 800 !important; margin: 20px 0 5px !important;
        }
        h3 {
          font-weight: 800 !important; margin: 20px 0 5px !important;
        }
        h4 {
          font-weight: 800 !important; margin: 20px 0 5px !important;
        }
        h1 {
          font-size: 22px !important;
        }
        h2 {
          font-size: 18px !important;
        }
        h3 {
          font-size: 16px !important;
        }
        .container {
          padding: 0 !important; width: 100% !important;
        }
        .content {
          padding: 0 !important;
        }
        .content-wrap {
          padding: 10px !important;
        }
        .invoice {
          width: 100% !important;
        }
      }
      </style>
      </head>
      
      <body itemscope itemtype="http://schema.org/EmailMessage" style="font-family: 'Helvetica Neue',Helvetica,Arial,     sans-serif; box-sizing: border-box; font-size: 14px; -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: none;     width: 100% !important; height: 100%; line-height: 1.6em; background-color: #f6f6f6; margin: 0;" bgcolor="#f6f6f6">
      
      <table class="body-wrap" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box;       font-size: 14px; width: 100%; background-color: #f6f6f6; margin: 0;" bgcolor="#f6f6f6"><tr style="font-family: 'Helvetica       Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td style="font-family: 'Helvetica       Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0;"       valign="top"></td>
          <td class="container" width="600" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing:      border-box; font-size: 14px; vertical-align: top; display: block !important; max-width: 600px !important; clear: both     !important; margin: 0 auto;" valign="top">
      <div class="content" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; max-width: 600px; display: block; margin: 0 auto; padding: 20px;">
        <table class="main" width="100%" cellpadding="0" cellspacing="0" itemprop="action" itemscope itemtype="http://schema.org/ConfirmAction" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; border-radius: 3px; background-color: #fff; margin: 0; border: 1px solid #e9e9e9;" bgcolor="#fff"><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="content-wrap" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 20px;" valign="top">
              <meta itemprop="name" content="Confirm Email" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;" /><table width="100%" cellpadding="0" cellspacing="0" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    Please confirm your email address by typing the next token on the link below: ${secretToken}
                  </td>
                </tr><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    We may need to send you critical information about our service and it is important that we have an accurate email address.
                  </td>
                </tr><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="content-block" itemprop="handler" itemscope itemtype="http://schema.org/HttpActionHandler" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    <a href="http://localhost:3000/users/verify" class="btn-primary" itemprop="url" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; color: #FFF; text-decoration: none; line-height: 2em; font-weight: bold; text-align: center; cursor: pointer; display: inline-block; border-radius: 5px; text-transform: capitalize; background-color: #348eda; margin: 0; border-color: #348eda; border-style: solid; border-width: 10px 20px;">Confirm email address</a>
                  </td>
                </tr><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
                    &mdash; BackLabs Corporation
                  </td>
                </tr></table></td>
          </tr></table><div class="footer" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; width: 100%; clear: both; color: #999; margin: 0; padding: 20px;">
          <table width="100%" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;"><td class="aligncenter content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 12px; vertical-align: top; color: #999; text-align: center; margin: 0; padding: 0 0 20px;" align="center" valign="top">Follow <a href="http://twitter.com/mail_gun" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 12px; color: #999; text-decoration: underline; margin: 0;">@Mail_Gun</a> on Twitter.</td>
            </tr></table></div></div>
          </td>
          <td style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px;   vertical-align: top; margin: 0;" valign="top"></td>
        </tr></table></body>
      </html>
      `;

      // Send the email
      await mailer.sendEmail(
        'admin@backlabs.com',
        result.value.email,
        'Please verify your email',
        html,
      );

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

router
  .route('/verify')
  .get(isNotAuthenticated, (req, res) => {
    res.render('verify');
  })
  .post(async (req, res, next) => {
    try {
      const { secretToken } = req.body;

      // Find the account that matches the secret token
      const user = await User.findOne({ secretToken });
      if (!user) {
        req.flash('error', 'User not found.');
        res.redirect('/users/verify');
      }

      user.active = true;
      user.secretToken = '';
      await user.save();

      req.flash('success', 'Awesome! Now you may login.');
      res.redirect('/users/login');
    } catch (error) {
      next(error);
    }
  });

router.route('/logout').get(isAuthenticated, (req, res) => {
  req.logOut();
  req.flash('success', 'You are logged out.');
  res.redirect('/');
});

module.exports = router;
