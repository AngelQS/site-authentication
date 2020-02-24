const express = require('express');
const router = express.Router();
const Joi = require('@hapi/joi');

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
    .regex(/^(?=.*\d)(?=.*[az])(?=.*[AZ])(?!.*\s).{8,}$/)
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

router
  .route('/register')
  .get((req, res) => {
    res.render('register');
  })
  .post((req, res, next) => {
    // console.log('req.body:', req.body);
    const result = userSchema.validate(req.body);
    console.log('result:', result);
    if (result.error) {
      req.flash('error', result.error.details[0].message);
      console.log('error:', result.error);
      res.redirect('/users/register');
    }
  });

router.route('/login').get((req, res) => {
  res.render('login');
});

module.exports = router;
