const { PrismaClient } = require('@prisma/client');
const { v4: uuidv4 } = require('uuid');

const prisma = new PrismaClient();

const createUser = async ({ utorid, name, email, password, role, verified }) => {
  const data = { utorid, name, email };

  // Add optional fields if provided
  if (password !== undefined) data.password = password;
  if (role !== undefined) data.role = role;
  if (verified !== undefined) data.verified = verified;

  // Generate reset token and expiration for new users
  data.resetToken = uuidv4();
  data.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

  return prisma.user.create({
    data,
    select: {
      id: true,
      utorid: true,
      name: true,
      email: true,
      verified: true,
      resetToken: true,
      expiresAt: true
    }
  });
};

const fetchUsers = async ({ name, role, verified, activated, page = 1, limit = 10 }) => {
  const where = {};

  if (name) {
    where.OR = [
      {
        name: {
          contains: name,
          mode: 'insensitive'
        }
      },
      {
        utorid: {
          contains: name,
          mode: 'insensitive'
        }
      }
    ];
  }

  if (role) {
    where.role = role;
  }

  if (typeof verified === 'boolean') {
    where.verified = verified;
  }

  if (typeof activated === 'boolean') {
    where.lastLogin = activated ? { not: null } : null;
  }

  const skip = (page - 1) * limit;

  const [count, results] = await Promise.all([
    prisma.user.count({ where }),
    prisma.user.findMany({
      where,
      skip,
      take: limit,
      orderBy: { id: 'asc' },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true
      }
    })
  ]);

  return { count, results };
};

module.exports = {
  createUser,
  fetchUsers
};
