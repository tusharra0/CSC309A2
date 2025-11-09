#!/usr/bin/env node
'use strict';

/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example:
 * node prisma/createsu.js <utorid> <email> <password>
 */

const { PrismaClient } = require('@prisma/client'); /// lets me tak to my sqlite database 
const bcrypt = require('bcrypt'); // library for hasing passwords, always store hash in your db and never the real password

const prisma = new PrismaClient(); // creates a new prsiam client instance so you can use it for queries, opening a connection to your database

async function main() {
  // Parse command-line arguments
  const args = process.argv.slice(2);
  if (args.length !== 3) {
    console.error("Usage: node prisma/createsu.js <utorid> <email> <password>");
    process.exit(1);
  }

  const [utorid, email, password] = args;

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({ where: { utorid } });
  if (existingUser) {
    console.error(`Error: User with utorid "${utorid}" already exists.`);
    process.exit(1);
  }

  // Hashing the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Creating a Superuser
  const newUser = await prisma.user.create({
    data: {
      utorid,
      email,
      name: "Super User",
      password: hashedPassword,
      role: "superuser",
      verified: true,
      suspicious: false,
      points: 0,
      createdAt: new Date(),
    },
  });

  // Printing Conformation of Creating a Superuser
  console.log("Superuser created successfully!");
  console.log({
    id: newUser.id,
    utorid: newUser.utorid,
    email: newUser.email,
    role: newUser.role,
    verified: newUser.verified,
  });
}

main()
  .catch((err) => {
    console.error("Error creating superuser:", err);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
