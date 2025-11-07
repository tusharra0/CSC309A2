/*
 * If you need to initialize your database with some data, you may write a script
 * to do so here.
 */
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  // No default users for autograder.
  console.log("Seed: no initial users.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

