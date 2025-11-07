const express = require('express');
const router = express.Router();
const { authRequired, requireRole } = require('../middleware/auth');
const { uploadAvatar, handleUploadError } = require('../middleware/upload');
const {
  createUser,
  getAllUsers,
  getUserById,
  updateUserById,
  getMyInfo,
  updateMyInfo,
  updateMyPassword
} = require('../controllers/userController');
const {
  createTransfer,
  createRedemptionRequest,
  getMyTransactions
} = require('../controllers/transactionsController');

// GET /users - Get all users with filters (requires manager or higher clearance)
router.get('/', authRequired, requireRole(['manager', 'superuser']), getAllUsers);

// POST /users - Create new user (requires cashier or higher clearance)
router.post('/', authRequired, requireRole(['cashier', 'manager', 'superuser']), createUser);

// GET /users/me - Get current logged-in user's information (requires authentication)
router.get('/me', authRequired, getMyInfo);

// PATCH /users/me - Update current logged-in user's information (requires authentication)
router.patch('/me', authRequired, uploadAvatar, handleUploadError, updateMyInfo);

// GET /users/me/transactions - List current user's transactions
router.get('/me/transactions', authRequired, getMyTransactions);

// POST /users/me/transactions - Create redemption request
router.post('/me/transactions', authRequired, createRedemptionRequest);

// PATCH /users/me/password - Update current logged-in user's password (requires authentication)
router.patch('/me/password', authRequired, requireRole(['regular', 'cashier', 'manager', 'superuser']), updateMyPassword);

// GET /users/:id - Get a specific user by ID (requires cashier or higher clearance)
router.get('/:id', authRequired, requireRole(['cashier', 'manager', 'superuser']), getUserById);

// POST /users/:id/transactions - Transfer points to another user
router.post('/:id/transactions', authRequired, createTransfer);

// PATCH /users/:id - Update a specific user by ID (requires manager or higher clearance)
router.patch('/:id', authRequired, requireRole(['manager', 'superuser']), updateUserById);

module.exports = router;
