/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example: 
 *   node prisma/createsu.js clive123 clive.su@mail.utoronto.ca SuperUser123!
 */

const { PrismaClient, RoleType } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();
const args = process.argv.slice(2);

if (args.length < 3) {
  console.log("Usage: node prisma/createsu.js <utorid> <email> <password>");
  process.exit(1);
}

const normalize = (value = "") => String(value).trim().toLowerCase();
const utorid = normalize(args[0]);
const email = normalize(args[1]);
const password = args[2];

const validUtorid = /^[a-z0-9]{7,8}$/i;
const validEmail = /^[^@\s]+@(?:mail\.)?utoronto\.ca$/i;

if (!utorid || !validUtorid.test(utorid)) {
  console.error("error: provide a valid UTORid");
  process.exit(1);
}

if (!email || !validEmail.test(email)) {
  console.error("error: provide a valid @utoronto.ca email");
  process.exit(1);
}

if (!password || password.trim().length === 0) {
  console.error("error: password is required");
  process.exit(1);
}

async function main() {
  const hashed = await bcrypt.hash(password, 10);

  const user = await prisma.user.upsert({
    where: { utorid },
    update: {
      email,
      name: utorid,
      password: hashed,
      role: RoleType.superuser,
      verified: true,
      suspicious: false,
      resetToken: null,
      expiresAt: null
    },
    create: {
      utorid,
      email,
      name: utorid,
      password: hashed,
      role: RoleType.superuser,
      verified: true,
      suspicious: false,
      resetToken: null,
      expiresAt: null
    },
    select: { id: true, utorid: true, email: true }
  });

  console.log(`Superuser ${user.utorid} (${user.email}) is ready.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
