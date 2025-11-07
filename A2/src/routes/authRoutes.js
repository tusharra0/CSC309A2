const express = require('express');
const router = express.Router();
const {
  login,
  requestPasswordReset,
  resetPasswordWithToken
} = require('../controllers/authController');

// POST /auth/tokens - Login endpoint
router.post('/tokens', login);

// POST /auth/resets - Request a password reset token
router.post('/resets', requestPasswordReset);

// POST /auth/resets/:resetToken - Complete password reset
router.post('/resets/:resetToken', resetPasswordWithToken);

module.exports = router;
