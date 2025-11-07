const promotionsService = require('../services/promotionsService');

const handle = async (res, action, status = 200) => {
  try {
    const payload = await action();
    if (status === 204) {
      return res.status(204).send();
    }
    return res.status(status).json(payload);
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Unexpected server error' });
  }
};

exports.createPromotion = (req, res) =>
  handle(res, () => promotionsService.createPromotion({ body: req.body, user: req.user }), 201);

exports.listPromotions = (req, res) =>
  handle(res, () => promotionsService.listPromotions({ user: req.user, query: req.query }));

exports.getPromotion = (req, res) => {
  const promotionId = Number(req.params.promotionId);
  if (!Number.isInteger(promotionId)) {
    return res.status(400).json({ message: 'Invalid promotion id' });
  }
  return handle(res, () =>
    promotionsService.getPromotionById({ promotionId, user: req.user })
  );
};

exports.updatePromotion = (req, res) => {
  const promotionId = Number(req.params.promotionId);
  if (!Number.isInteger(promotionId)) {
    return res.status(400).json({ message: 'Invalid promotion id' });
  }
  return handle(res, () =>
    promotionsService.updatePromotion({ promotionId, user: req.user, body: req.body })
  );
};

exports.deletePromotion = (req, res) => {
  const promotionId = Number(req.params.promotionId);
  if (!Number.isInteger(promotionId)) {
    return res.status(400).json({ message: 'Invalid promotion id' });
  }
  return handle(
    res,
    () => promotionsService.deletePromotion({ promotionId, user: req.user }),
    204
  );
};
