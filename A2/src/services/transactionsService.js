const { PrismaClient, TransactionType } = require('@prisma/client');
const { calculateBasePoints, calculatePromotionBonuses } = require('./pointsService');

const prisma = new PrismaClient();

const createError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const transactionInclude = {
  user: true,
  sender: true,
  recipient: true,
  createdBy: true,
  processedBy: true,
  promotions: true,
  event: true
};

const normalizeNumber = (value) => {
  if (value === null || value === undefined) return NaN;
  const numeric = typeof value === 'string' ? Number(value) : value;
  return Number(numeric);
};

const normalizeBoolean = (value) => {
  if (value === undefined) return undefined;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }
  return undefined;
};

const parseIdArray = (input) => {
  if (!input) return [];
  if (Array.isArray(input)) return input.map((id) => Number(id)).filter((id) => Number.isInteger(id));
  if (typeof input === 'string') {
    return input
      .split(',')
      .map((id) => Number(id.trim()))
      .filter((id) => Number.isInteger(id));
  }
  return [];
};

const validatePromotions = async (tx, promotionIds, { spent, userId }) => {
  if (!promotionIds || promotionIds.length === 0) return [];

  const promotions = await tx.promotion.findMany({
    where: { id: { in: promotionIds } }
  });

  if (promotions.length !== promotionIds.length) {
    throw createError(400, 'Promotion not active');
  }

  const orderedPromotions = promotionIds.map((id) => promotions.find((promotion) => promotion.id === id));
  const now = new Date();

  for (const promotion of orderedPromotions) {
    if (!promotion) {
      throw createError(400, 'Promotion not active');
    }

    if ((promotion.startTime && promotion.startTime > now) || (promotion.endTime && promotion.endTime < now)) {
      throw createError(400, 'Promotion not active');
    }

    if (promotion.minSpending && spent < promotion.minSpending) {
      throw createError(400, 'Promotion already used');
    }

    if (promotion.oneTime) {
      const usage = await tx.promotionUsage.findUnique({
        where: {
          promotionId_userId: {
            promotionId: promotion.id,
            userId
          }
        }
      });

      if (usage) {
        throw createError(400, 'Promotion already used');
      }
    }
  }

  return orderedPromotions;
};

const createPurchaseTransaction = async ({ creatorId, utorid, spent, promotionIds = [], remark }) => {
  const numericSpent = normalizeNumber(spent);
  if (!Number.isFinite(numericSpent) || numericSpent <= 0) {
    throw createError(400, 'Spent must be a positive number');
  }

  const uniquePromotionIds = [...new Set(parseIdArray(promotionIds))];

  return prisma.$transaction(async (tx) => {
    const [targetUser, creator] = await Promise.all([
      tx.user.findUnique({ where: { utorid } }),
      tx.user.findUnique({ where: { id: creatorId } })
    ]);

    if (!targetUser) {
      throw createError(404, 'User not found');
    }

    if (!creator) {
      throw createError(401, 'Unauthorized');
    }

    const promotions = await validatePromotions(tx, uniquePromotionIds, {
      spent: numericSpent,
      userId: targetUser.id
    });

    const basePoints = calculateBasePoints(numericSpent);
    const { totalPoints, applications } = calculatePromotionBonuses(basePoints, promotions, numericSpent);
    const isSuspicious = creator.role === 'cashier' && creator.suspicious;
    const creditedPoints = isSuspicious ? 0 : totalPoints;

    const created = await tx.transaction.create({
      data: {
        type: TransactionType.purchase,
        pointsDelta: totalPoints,
        spent: numericSpent,
        remark,
        suspicious: isSuspicious,
        userId: targetUser.id,
        createdById: creatorId
      }
    });

    if (applications.length) {
      await Promise.all(
        applications.map((application) =>
          tx.transactionPromotion.create({
            data: {
              transactionId: created.id,
              promotionId: application.promotionId,
              bonusPoints: application.bonus
            }
          })
        )
      );
    }

    if (promotions.some((promotion) => promotion.oneTime)) {
      await Promise.all(
        promotions
          .filter((promotion) => promotion.oneTime)
          .map((promotion) =>
            tx.promotionUsage.create({
              data: {
                promotionId: promotion.id,
                userId: targetUser.id
              }
            })
          )
      );
    }

    if (!isSuspicious && totalPoints !== 0) {
      await tx.user.update({
        where: { id: targetUser.id },
        data: {
          points: { increment: totalPoints }
        }
      });
    }

    const transaction = await tx.transaction.findUnique({
      where: { id: created.id },
      include: transactionInclude
    });

    return {
      transaction,
      targetUser,
      creator,
      promotionIds: uniquePromotionIds,
      creditedPoints
    };
  });
};

const createAdjustmentTransaction = async ({ creatorId, utorid, amount, relatedId, remark }) => {
  const numericAmount = normalizeNumber(amount);
  if (!Number.isFinite(numericAmount) || numericAmount === 0) {
    throw createError(400, 'Amount must be a valid number');
  }

  return prisma.$transaction(async (tx) => {
    const [targetUser, related] = await Promise.all([
      tx.user.findUnique({ where: { utorid } }),
      relatedId ? tx.transaction.findUnique({ where: { id: relatedId } }) : null
    ]);

    if (!targetUser) {
      throw createError(404, 'User not found');
    }

    if (relatedId && !related) {
      throw createError(404, 'Related transaction not found');
    }

    await tx.user.update({
      where: { id: targetUser.id },
      data: {
        points: { increment: numericAmount }
      }
    });

    const transaction = await tx.transaction.create({
      data: {
        type: TransactionType.adjustment,
        pointsDelta: numericAmount,
        remark,
        userId: targetUser.id,
        createdById: creatorId,
        relatedTransactionId: related ? related.id : null
      },
      include: transactionInclude
    });

    return {
      transaction,
      targetUser
    };
  });
};

const buildTransactionsWhere = (filters = {}) => {
  const where = {};

  if (filters.type) {
    where.type = filters.type;
  }

  if (filters.relatedId) {
    where.relatedTransactionId = filters.relatedId;
  }

  const suspiciousFilter = normalizeBoolean(filters.suspicious);
  if (suspiciousFilter !== undefined) {
    where.suspicious = suspiciousFilter;
  }

  if (filters.promotionId) {
    where.promotions = {
      some: {
        promotionId: filters.promotionId
      }
    };
  }

  if (filters.createdBy) {
    where.createdBy = {
      utorid: filters.createdBy
    };
  }

  const amountGte = normalizeNumber(filters.amountGte ?? filters.amount_gte);
  const amountLte = normalizeNumber(filters.amountLte ?? filters.amount_lte);

  if (Number.isFinite(amountGte) || Number.isFinite(amountLte)) {
    where.pointsDelta = {};
    if (Number.isFinite(amountGte)) {
      where.pointsDelta.gte = amountGte;
    }
    if (Number.isFinite(amountLte)) {
      where.pointsDelta.lte = amountLte;
    }
  }

  if (filters.name) {
    const name = filters.name;
    where.OR = [
      { user: { name: { contains: name, mode: 'insensitive' } } },
      { user: { utorid: { contains: name, mode: 'insensitive' } } },
      { sender: { name: { contains: name, mode: 'insensitive' } } },
      { sender: { utorid: { contains: name, mode: 'insensitive' } } },
      { recipient: { name: { contains: name, mode: 'insensitive' } } },
      { recipient: { utorid: { contains: name, mode: 'insensitive' } } }
    ];
  }

  return where;
};

const listTransactions = async (params = {}) => {
  const page = Math.max(Number(params.page) || 1, 1);
  const limit = Math.min(Math.max(Number(params.limit) || 10, 1), 100);

  const where = buildTransactionsWhere({
    type: params.type,
    suspicious: params.suspicious,
    name: params.name,
    createdBy: params.createdBy,
    promotionId: params.promotionId ? Number(params.promotionId) : undefined,
    relatedId: params.relatedId ? Number(params.relatedId) : undefined,
    amountGte: params.amountGte ?? params['amount[gte]'],
    amountLte: params.amountLte ?? params['amount[lte]'],
    amount_gte: params['amount[gte]'],
    amount_lte: params['amount[lte]']
  });

  const [count, records] = await prisma.$transaction([
    prisma.transaction.count({ where }),
    prisma.transaction.findMany({
      where,
      include: transactionInclude,
      orderBy: { id: 'asc' },
      skip: (page - 1) * limit,
      take: limit
    })
  ]);

  return { count, records };
};

const findTransactionById = async (transactionId) => {
  const transaction = await prisma.transaction.findUnique({
    where: { id: transactionId },
    include: transactionInclude
  });

  if (!transaction) {
    throw createError(404, 'Transaction not found');
  }

  return transaction;
};

const setTransactionSuspicious = async (transactionId, nextValue) => {
  const desiredValue = Boolean(nextValue);

  return prisma.$transaction(async (tx) => {
    const transaction = await tx.transaction.findUnique({
      where: { id: transactionId },
      include: transactionInclude
    });

    if (!transaction) {
      throw createError(404, 'Transaction not found');
    }

    if (transaction.type !== TransactionType.purchase) {
      throw createError(400, 'Only purchase transactions can be updated');
    }

    if (transaction.suspicious === desiredValue) {
      return transaction;
    }

    if (transaction.userId && transaction.pointsDelta) {
      const adjustment = desiredValue ? -transaction.pointsDelta : transaction.pointsDelta;
      await tx.user.update({
        where: { id: transaction.userId },
        data: {
          points: { increment: adjustment }
        }
      });
    }

    return tx.transaction.update({
      where: { id: transactionId },
      data: {
        suspicious: desiredValue
      },
      include: transactionInclude
    });
  });
};

const processRedemption = async (transactionId, processorId) => {
  return prisma.$transaction(async (tx) => {
    const transaction = await tx.transaction.findUnique({
      where: { id: transactionId },
      include: transactionInclude
    });

    if (!transaction) {
      throw createError(404, 'Transaction not found');
    }

    if (transaction.type !== TransactionType.redemption) {
      throw createError(400, 'Invalid transaction type');
    }

    if (transaction.processed) {
      throw createError(400, 'Transaction already processed');
    }

    if (!transaction.userId || !transaction.pointsDelta) {
      throw createError(400, 'Redemption cannot be processed');
    }

    const user = await tx.user.findUnique({ where: { id: transaction.userId } });
    if (!user) {
      throw createError(404, 'User not found');
    }

    if (user.points < transaction.pointsDelta) {
      throw createError(400, 'Insufficient points');
    }

    await tx.user.update({
      where: { id: user.id },
      data: {
        points: { decrement: transaction.pointsDelta }
      }
    });

    return tx.transaction.update({
      where: { id: transactionId },
      data: {
        processed: true,
        processedAt: new Date(),
        processedById: processorId
      },
      include: transactionInclude
    });
  });
};

const createTransfer = async ({ senderId, recipientId, amount, remark }) => {
  const numericAmount = normalizeNumber(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    throw createError(400, 'Amount must be a positive number');
  }

  if (senderId === recipientId) {
    throw createError(400, 'Cannot transfer to yourself');
  }

  return prisma.$transaction(async (tx) => {
    const [sender, recipient] = await Promise.all([
      tx.user.findUnique({ where: { id: senderId } }),
      tx.user.findUnique({ where: { id: recipientId } })
    ]);

    if (!sender) {
      throw createError(401, 'Unauthorized');
    }

    if (!recipient) {
      throw createError(404, 'User not found');
    }

    if (sender.points < numericAmount) {
      throw createError(400, 'Insufficient points');
    }

    await tx.user.update({
      where: { id: sender.id },
      data: {
        points: { decrement: numericAmount }
      }
    });

    await tx.user.update({
      where: { id: recipient.id },
      data: {
        points: { increment: numericAmount }
      }
    });

    const transaction = await tx.transaction.create({
      data: {
        type: TransactionType.transfer,
        pointsDelta: -numericAmount,
        remark,
        userId: sender.id,
        senderId: sender.id,
        recipientId: recipient.id,
        createdById: sender.id
      },
      include: transactionInclude
    });

    return {
      transaction,
      sender,
      recipient
    };
  });
};

const createRedemptionRequest = async ({ userId, amount, remark }) => {
  const numericAmount = normalizeNumber(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    throw createError(400, 'Amount must be a positive number');
  }

  return prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw createError(401, 'Unauthorized');
    }

    if (user.points < numericAmount) {
      throw createError(400, 'Insufficient points');
    }

    const transaction = await tx.transaction.create({
      data: {
        type: TransactionType.redemption,
        pointsDelta: numericAmount,
        remark,
        userId: user.id,
        createdById: user.id
      },
      include: transactionInclude
    });

    return {
      transaction,
      user
    };
  });
};

const listUserTransactions = async ({ userId, page = 1, limit = 10 }) => {
  const safePage = Math.max(Number(page) || 1, 1);
  const safeLimit = Math.min(Math.max(Number(limit) || 10, 1), 100);

  const where = {
    OR: [
      { userId },
      { senderId: userId },
      { recipientId: userId }
    ]
  };

  const [count, records] = await prisma.$transaction([
    prisma.transaction.count({ where }),
    prisma.transaction.findMany({
      where,
      include: transactionInclude,
      orderBy: { id: 'asc' },
      skip: (safePage - 1) * safeLimit,
      take: safeLimit
    })
  ]);

  return { count, records };
};

module.exports = {
  createPurchaseTransaction,
  createAdjustmentTransaction,
  listTransactions,
  findTransactionById,
  setTransactionSuspicious,
  processRedemption,
  createTransfer,
  createRedemptionRequest,
  listUserTransactions,
  createError
};
