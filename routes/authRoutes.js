const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');
const roleMiddleware = require('../middleware/roleMiddleware');

// Registration and login
router.post('/register', authController.register);
router.post('/login', authController.login);

// OTP verification
router.post('/verify-otp', authController.verifyRegistrationOtp); // For registration
router.post('/verify-reset-otp', authController.verifyResetOtp); // For password reset

// Password reset flow
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Resend OTP for email verification
router.post('/resend-otp', authController.resendOtp);

// Refresh token
router.post('/refresh-token', authController.refreshToken);

// Protected route example (admin only)
router.get('/admin-only', authMiddleware, roleMiddleware('admin'), (req, res) => {
  res.json({ message: `Hello Admin ${req.user.name}` });
});

// Protected route example 
router.get('/dashboard', authMiddleware, roleMiddleware('user', 'admin'), (req, res) => {
  res.json({ message: `Welcome ${req.user.name}, role: ${req.user.role}` });
});

// Verified users route 
router.get('/verified-users', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const verifiedUsers = await User.find({ isVerified: true })
      .select('name email role createdAt');

    res.json({
      count: verifiedUsers.length,
      users: verifiedUsers.map(user => ({
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        registeredAt: user.createdAt
      }))
    });
  } catch (err) {
    console.error('Error fetching verified users:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
