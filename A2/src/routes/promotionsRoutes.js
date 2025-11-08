const express = require('express');
const router = express.Router();
const promotionsController = require('../controllers/promotionsController');
const { authRequired } = require('../middleware/auth');

router.post('/', authRequired, promotionsController.createPromotion);

// GET /promotions
router.get('/', authRequired, promotionsController.listPromotions);

// GET /promotions/:promotionId
router.get('/:promotionId', authRequired, promotionsController.getPromotion);

// PATCH /promotions/:promotionId
router.patch('/:promotionId', authRequired, promotionsController.updatePromotion);

// DELETE /promotions/:promotionId
router.delete('/:promotionId', authRequired, promotionsController.deletePromotion);

module.exports = router;