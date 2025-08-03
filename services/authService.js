const User = require('../models/User');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const tokenUtils = require('../utils/tokenUtils');

const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: '15m'
  });
};

const registerUser = async ({ name, email, password, role }) => {
  if (role === 'admin') {
    const adminCount = await User.countDocuments({ role: 'admin' });
    if (adminCount >= 5) {
      throw new Error('Maximum number of admins reached');
    }
  }

  const verificationToken = crypto.randomBytes(32).toString('hex');

  const user = await User.create({
    name,
    email,
    password,
    role: role || 'user',
    verificationToken
  });

  const verifyLink = `https://kavindu.unisalpila.store/api/auth/verify-email?token=${verificationToken}`;
  await sendEmail(email, 'Verify your email', verifyLink);

  return user;
};

const verifyEmailToken = async (token) => {
  const user = await User.findOne({ verificationToken: token });
  if (!user) throw new Error('Invalid token');

  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();
};

const loginUser = async ({ email, password }) => {
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.comparePassword(password))) {
    throw new Error('Invalid credentials');
  }

  if (!user.isVerified) {
    throw new Error('Please verify your email first');
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = tokenUtils.generateRefreshToken();

  user.refreshToken = refreshToken;
  await user.save();

  return { accessToken, refreshToken };
};

const refreshAccessToken = async (refreshToken) => {
  const user = await User.findOne({ refreshToken });
  if (!user) throw new Error('Invalid refresh token');

  return generateAccessToken(user);
};

const initiatePasswordReset = async (email) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error('User not found');

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  await user.save();

  const resetLink = `https://kavindu.unisalpila.store/api/auth/reset-password?token=${resetToken}`;
  await sendEmail(email, 'Reset your password', resetLink);
};

const resetPassword = async (token, newPassword) => {
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) throw new Error('Invalid or expired token');

  user.password = newPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();
};

module.exports = {
  registerUser,
  verifyEmailToken,
  loginUser,
  refreshAccessToken,
  initiatePasswordReset,
  resetPassword
};
