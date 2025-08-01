const crypto = require('crypto');

/**
 * Generate a secure random refresh token
 * @returns {string} A 64-byte hex string
 */
const generateRefreshToken = () => {
  return crypto.randomBytes(64).toString('hex');
};

module.exports = {
  generateRefreshToken
};
