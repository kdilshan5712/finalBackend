const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');
const tokenUtils = require('../utils/tokenUtils');

// Generate Access Token
const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: '15m'
  });
};

// 📌 Register with OTP
exports.register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (role === 'admin') {
      const adminCount = await User.countDocuments({ role: 'admin' });
      if (adminCount >= 5) {
        return res.status(403).json({ message: 'Maximum number of admins reached' });
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

    const user = await User.create({
      name,
      email,
      password,
      role: role || 'user',
      isVerified: false,
      verificationOtp: hashedOtp,
      verificationOtpExpires: Date.now() + 10 * 60 * 1000 // 10 minutes
    });

    await sendEmail(email, 'Email Verification OTP', otp);

    res.status(201).json({ message: 'Registration successful. Please verify your email using the OTP sent.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 📌 Verify Registration OTP
exports.verifyRegistrationOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

    if (
      user.verificationOtp !== hashedOtp ||
      user.verificationOtpExpires < Date.now()
    ) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    user.isVerified = true;
    user.verificationOtp = null;
    user.verificationOtpExpires = null;
    await user.save();

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 📌 Login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password +isVerified +role +name');

    if (!user || !(await user.comparePassword(password))) {
      console.log(`❌ Login failed for email: ${email} - Invalid credentials`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      console.log(`⚠️ Login failed for email: ${email} - Email not verified`);
      return res.status(403).json({
        message: 'Email not verified. Please check your inbox or request a new OTP.'
      });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = tokenUtils.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save();

    const firstName = user.name.split(' ')[0];

    console.log(`✅ Login successful for email: ${email}`);

    res.status(200).json({
      accessToken,
      refreshToken,
      name: firstName,
      role: user.role
    });

  } catch (err) {
    console.error(`🔥 Login error for email: ${req.body.email} - ${err.message}`);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// 📌 Refresh Token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findOne({ refreshToken });

    if (!user) return res.status(403).json({ message: 'Invalid refresh token' });

    const newAccessToken = generateAccessToken(user);
    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 📌 Forgot Password (Send OTP)
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetPasswordToken = otp;
    user.resetPasswordExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    await sendEmail(email, 'Password Reset OTP', otp);

    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error('🔥 Forgot Password Error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// 📌 Verify Reset OTP
exports.verifyResetOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (
      user.resetPasswordToken !== otp ||
      user.resetPasswordExpires < Date.now()
    ) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    res.status(200).json({ message: 'OTP verified' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 📌 Reset Password
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const user = await User.findOne({ email });

    if (!user || user.resetPasswordToken !== otp || user.resetPasswordExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    user.password = newPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// 📌 Resend OTP
exports.resendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Email is already verified' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

    user.verificationOtp = hashedOtp;
    user.verificationOtpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    await sendEmail(email, 'Resend Verification OTP', otp);

    res.status(200).json({ message: 'New OTP sent successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};
