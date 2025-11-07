/*
 * If you need to initialize your database with some data, you may write a script
 * to do so here.
 */
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const prisma = new PrismaClient();

async function main() {
  const users = [];
  for (let i = 1; i <= 22; i++) {
    users.push({
      utorid: `user${i}`,
      name: `User ${i}`,
      email: `user${i}@mail.utoronto.ca`,
      password: await bcrypt.hash("Password123!", 10),
      verified: true,
      role: i === 1 ? "superuser" : "regular",
      points: 100
    });
  }
  await prisma.user.createMany({ data: users });
  console.log("Seeded 22 users ✅");
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());

