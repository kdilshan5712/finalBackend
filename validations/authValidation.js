const Joi = require('joi');

// Registration validation
const registerSchema = Joi.object({
  name: Joi.string().min(3).max(50).required().messages({
    'string.base': 'Name must be a string',
    'string.empty': 'Name is required',
    'string.min': 'Name must be at least 3 characters',
    'string.max': 'Name must be less than 50 characters'
  }),
  email: Joi.string().email().required().messages({
    'string.email': 'Please enter a valid email',
    'string.empty': 'Email is required'
  }),
  password: Joi.string().min(6).required().messages({
    'string.min': 'Password must be at least 6 characters',
    'string.empty': 'Password is required'
  }),
  role: Joi.string().valid('user', 'admin').optional()
});

// Login validation
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// Forgot password validation
const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

// Reset password validation
const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  newPassword: Joi.string().min(6).required()
});

// Email verification schema (if using token in body)
const emailVerificationSchema = Joi.object({
  token: Joi.string().required()
});

module.exports = {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  emailVerificationSchema
};
