#!/usr/bin/env node
'use strict';

/**
 * Seed script to populate the database with test users for each role
 * Usage: node prisma/seed.js
 */

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  console.log('Starting database seed...\n');

  // Define test users for each role
  const users = [
    // 5 Regular users - no passwords
    { utorid: 'regular1', name: 'Alice Regular', email: 'alice@mail.utoronto.ca', role: 'regular', verified: true },
    { utorid: 'regular2', name: 'Bob Regular', email: 'bob@mail.utoronto.ca', role: 'regular', verified: true },
    { utorid: 'regular3', name: 'Charlie Regular', email: 'charlie@mail.utoronto.ca', role: 'regular', verified: false },
    { utorid: 'regular4', name: 'Diana Regular', email: 'diana@mail.utoronto.ca', role: 'regular', verified: true },
    { utorid: 'regular5', name: 'Eve Regular', email: 'eve@mail.utoronto.ca', role: 'regular', verified: false },

    // 1 Cashier - with password
    { utorid: 'cashier1', name: 'Frank Cashier', email: 'frank@mail.utoronto.ca', password: 'cashier123', role: 'cashier', verified: true },

    // 1 Superuser - with password
    { utorid: 'superuser', name: 'Super User', email: 'superuser@mail.utoronto.ca', password: 'super123', role: 'superuser', verified: true },
  ];

  for (const userData of users) {
    try {
      // Check if user already exists
      const existing = await prisma.user.findUnique({
        where: { utorid: userData.utorid }
      });

      if (existing) {
        console.log(`⏭️  Skipping ${userData.utorid} (already exists)`);
        continue;
      }

      // Hash password if provided
      const data = {
        utorid: userData.utorid,
        name: userData.name,
        email: userData.email,
        role: userData.role,
        verified: userData.verified,
        suspicious: false,
        points: 0,
      };

      if (userData.password) {
        data.password = await bcrypt.hash(userData.password, 10);
      }

      // Create user
      const user = await prisma.user.create({ data });

      console.log(`✅ Created ${user.role.padEnd(10)} | ${user.utorid.padEnd(12)} | ${userData.password ? `password: ${userData.password}` : 'no password'}`);

    } catch (err) {
      console.error(`❌ Failed to create ${userData.utorid}:`, err.message);
    }
  }

  console.log('\n✅ Database seeding completed!\n');
  console.log('Test Credentials Summary:');
  console.log('═══════════════════════════════════════════════════════');
  console.log('Regular Users (no password):');
  console.log('  - regular1, regular2, regular3, regular4, regular5');
  console.log('');
  console.log('Cashier (can view limited user info):');
  console.log('  - utorid: cashier1, password: cashier123');
  console.log('');
  console.log('Superuser (full access):');
  console.log('  - utorid: superuser, password: super123');
  console.log('═══════════════════════════════════════════════════════\n');
}

main()
  .catch((err) => {
    console.error('❌ Error during seeding:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
