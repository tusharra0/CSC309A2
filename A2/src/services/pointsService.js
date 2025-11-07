const calculateBasePoints = (spent) => {
  if (typeof spent !== 'number' || Number.isNaN(spent)) {
    return 0;
  }
  return Math.round(spent / 0.25);
};

const calculatePromotionBonuses = (basePoints, promotions = [], spent = 0) => {
  const applications = [];
  let bonusTotal = 0;

  promotions.forEach((promotion) => {
    let bonus = 0;

    if (typeof promotion.rate === 'number' && promotion.rate > 0) {
      bonus += Math.round(spent * promotion.rate * 100);
    }

    if (typeof promotion.points === 'number' && promotion.points > 0) {
      bonus += promotion.points;
    }

    if (bonus < 0) bonus = 0;

    applications.push({
      promotionId: promotion.id,
      bonus
    });

    bonusTotal += bonus;
  });

  return {
    totalPoints: Math.max(basePoints + bonusTotal, 0),
    applications
  };
};

module.exports = {
  calculateBasePoints,
  calculatePromotionBonuses
};
