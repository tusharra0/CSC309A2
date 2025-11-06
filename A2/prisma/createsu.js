/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example: 
 *   node prisma/createsu.js clive123 clive.su@mail.utoronto.ca SuperUser123!
 */

const { PrismaClient } = require('@prisma/client'); // lets us talk to the database
const bcrypt = require('bcrypt'); // helps encrypt the password
const prisma = new PrismaClient(); // create a database connection

const args = process.argv.slice(2);
if (args.length < 3) {
  console.log("Example: node prisma/createsu.js clive123 clive@mail.utoronto.ca StrongPass123!");
  process.exit(1);
}

const utorid = args[0];
const email = args[1];
const password = args[2];


async function main() {
  const hashed = await bcrypt.hash(password, 10);

  await prisma.user.create({
    data: {
      utorid: utorid,
      email: email,
      name: utorid,
      password: hashed,
      role: 'superuser',
      verified: true
    }
  });

  console.log("Super user added to the db")
}
main()
  .then(() => prisma.$disconnect())
  .catch((err) => {
    console.error(err);
    prisma.$disconnect();
  });
  