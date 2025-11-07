const transactionsService = require('../services/transactionsService');

const toPromotionIds = (transaction) =>
  Array.isArray(transaction.promotions) ? transaction.promotions.map((item) => item.promotionId) : [];

const baseCreatedBy = (transaction) => transaction.createdBy?.utorid ?? null;

const formatTransaction = (transaction) => {
  switch (transaction.type) {
    case 'purchase':
      return {
        id: transaction.id,
        utorid: transaction.user?.utorid ?? null,
        amount: transaction.pointsDelta,
        type: 'purchase',
        spent: transaction.spent ?? 0,
        promotionIds: toPromotionIds(transaction),
        suspicious: transaction.suspicious,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
    case 'adjustment':
      return {
        id: transaction.id,
        utorid: transaction.user?.utorid ?? null,
        amount: transaction.pointsDelta,
        type: 'adjustment',
        relatedId: transaction.relatedTransactionId ?? null,
        promotionIds: toPromotionIds(transaction),
        suspicious: transaction.suspicious,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
    case 'transfer':
      return {
        id: transaction.id,
        sender: transaction.sender?.utorid ?? null,
        recipient: transaction.recipient?.utorid ?? null,
        type: 'transfer',
        sent: transaction.pointsDelta,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
    case 'redemption':
      return {
        id: transaction.id,
        utorid: transaction.user?.utorid ?? null,
        type: 'redemption',
        amount: transaction.pointsDelta,
        processed: transaction.processed,
        processedBy: transaction.processedBy?.utorid ?? null,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
    case 'event':
      return {
        id: transaction.id,
        recipient: transaction.recipient?.utorid ?? transaction.user?.utorid ?? null,
        awarded: transaction.pointsDelta,
        type: 'event',
        eventId: transaction.eventId ?? null,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
    default:
      return {
        id: transaction.id,
        type: transaction.type,
        amount: transaction.pointsDelta,
        remark: transaction.remark ?? null,
        createdBy: baseCreatedBy(transaction)
      };
  }
};

const permissionError = (res) =>
  res.status(403).json({ message: 'Insufficient permission to preform this action.' });

const handleServiceAction = async (res, action, successStatus = 200) => {
  try {
    const payload = await action();
    return res.status(successStatus).json(payload);
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Unexpected server error' });
  }
};

exports.createTransaction = async (req, res) => {
  const body = req.body || {};
  const type = body.type;
  const actorId = req.user?.id;

  if (!actorId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!['cashier', 'manager', 'superuser'].includes(req.user?.role)) {
    return permissionError(res);
  }

  if (type === 'purchase') {
    return handleServiceAction(
      res,
      async () => {
        const result = await transactionsService.createPurchaseTransaction({
          creatorId: actorId,
          utorid: body.utorid,
          spent: body.spent,
          promotionIds: body.promotionIds,
          remark: body.remark
        });

        return {
          id: result.transaction.id,
          utorid: result.targetUser.utorid,
          type: 'purchase',
          spent: result.transaction.spent ?? 0,
          earned: result.creditedPoints,
          remark: result.transaction.remark ?? null,
          promotionIds: result.promotionIds,
          createdBy: req.user?.utorid ?? null
        };
      },
      201
    );
  }

  if (type === 'adjustment') {
    if (!['manager', 'superuser'].includes(req.user?.role)) {
      return permissionError(res);
    }

    return handleServiceAction(
      res,
      async () => {
        const result = await transactionsService.createAdjustmentTransaction({
          creatorId: actorId,
          utorid: body.utorid,
          amount: body.amount,
          relatedId: body.relatedId,
          remark: body.remark
        });

        return {
          id: result.transaction.id,
          utorid: result.targetUser.utorid,
          type: 'adjustment',
          amount: result.transaction.pointsDelta,
          relatedId: result.transaction.relatedTransactionId ?? null,
          promotionIds: toPromotionIds(result.transaction),
          remark: result.transaction.remark ?? null,
          createdBy: req.user?.utorid ?? null
        };
      },
      201
    );
  }

  return res.status(400).json({ message: 'Unsupported transaction type' });
};

exports.getTransactions = async (req, res) => {
  if (!['manager', 'superuser'].includes(req.user?.role)) {
    return permissionError(res);
  }

  try {
    const { count, records } = await transactionsService.listTransactions(req.query);
    return res.status(200).json({
      count,
      results: records.map(formatTransaction)
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Failed to fetch transactions' });
  }
};

exports.getTransactionById = async (req, res) => {
  if (!['manager', 'superuser'].includes(req.user?.role)) {
    return permissionError(res);
  }

  const transactionId = Number(req.params.transactionId);
  if (!Number.isInteger(transactionId)) {
    return res.status(400).json({ message: 'Invalid transaction id' });
  }

  try {
    const transaction = await transactionsService.findTransactionById(transactionId);
    return res.status(200).json(formatTransaction(transaction));
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Failed to fetch transaction' });
  }
};

exports.updateTransactionSuspicious = async (req, res) => {
  if (!['manager', 'superuser'].includes(req.user?.role)) {
    return permissionError(res);
  }

  const transactionId = Number(req.params.transactionId);
  if (!Number.isInteger(transactionId)) {
    return res.status(400).json({ message: 'Invalid transaction id' });
  }

  if (typeof req.body?.suspicious !== 'boolean') {
    return res.status(400).json({ message: 'Suspicious flag is required' });
  }

  return handleServiceAction(res, async () => {
    const updated = await transactionsService.setTransactionSuspicious(transactionId, req.body.suspicious);
    return formatTransaction(updated);
  });
};

exports.processTransaction = async (req, res) => {
  if (!['cashier', 'manager', 'superuser'].includes(req.user?.role)) {
    return permissionError(res);
  }

  const transactionId = Number(req.params.transactionId);
  if (!Number.isInteger(transactionId)) {
    return res.status(400).json({ message: 'Invalid transaction id' });
  }

  if (req.body?.processed !== true) {
    return res.status(400).json({ message: 'Processed flag is required' });
  }

  const processorId = req.user?.id;
  if (!processorId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  return handleServiceAction(res, async () => {
    const transaction = await transactionsService.processRedemption(transactionId, processorId);
    return {
      id: transaction.id,
      utorid: transaction.user?.utorid ?? null,
      type: 'redemption',
      processedBy: transaction.processedBy?.utorid ?? null,
      redeemed: transaction.pointsDelta,
      remark: transaction.remark ?? null,
      createdBy: baseCreatedBy(transaction)
    };
  });
};

exports.createTransfer = async (req, res) => {
  const senderId = req.user?.id;
  if (!senderId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const recipientId = Number(req.params.id);
  if (!Number.isInteger(recipientId)) {
    return res.status(400).json({ message: 'Invalid user ID' });
  }

  if (req.body?.type && req.body.type !== 'transfer') {
    return res.status(400).json({ message: 'Unsupported transaction type' });
  }

  return handleServiceAction(
    res,
    async () => {
      const result = await transactionsService.createTransfer({
        senderId,
        recipientId,
        amount: req.body?.amount,
        remark: req.body?.remark
      });

      return {
        id: result.transaction.id,
        sender: result.sender.utorid,
        recipient: result.recipient.utorid,
        type: 'transfer',
        sent: Math.abs(result.transaction.pointsDelta),
        remark: result.transaction.remark ?? null,
        createdBy: result.sender.utorid
      };
    },
    201
  );
};

exports.createRedemptionRequest = async (req, res) => {
  const userId = req.user?.id;
  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (req.body?.type !== 'redemption') {
    return res.status(400).json({ message: 'Unsupported transaction type' });
  }

  return handleServiceAction(
    res,
    async () => {
      const result = await transactionsService.createRedemptionRequest({
        userId,
        amount: req.body?.amount,
        remark: req.body?.remark
      });

      return {
        id: result.transaction.id,
        utorid: result.user.utorid,
        type: 'redemption',
        processedBy: null,
        amount: result.transaction.pointsDelta,
        remark: result.transaction.remark ?? null,
        createdBy: result.user.utorid
      };
    },
    201
  );
};

exports.getMyTransactions = async (req, res) => {
  const userId = req.user?.id;
  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const { count, records } = await transactionsService.listUserTransactions({
      userId,
      page: req.query.page,
      limit: req.query.limit
    });
    return res.status(200).json({
      count,
      results: records.map(formatTransaction)
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({ message: err.message });
    }
    console.error(err);
    return res.status(500).json({ message: 'Failed to fetch transactions' });
  }
};
