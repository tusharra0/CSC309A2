#!/usr/bin/env node
'use strict';

const port = (() => {
    const args = process.argv;

    if (args.length !== 3) {
        console.error("usage: node index.js port");
        process.exit(1);
    }

    const num = parseInt(args[2], 10);
    if (isNaN(num)) {
        console.error("error: argument must be an integer.");
        process.exit(1);
    }

    return num;
})();

const express = require("express");
const app = express();

app.use(express.json());

const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const prisma = new PrismaClient();


// Create a new user
app.post("/users", async (req, res) => {
  try {
    const { utorid, email, name, password } = req.body;

    // Basic validation
    if (!utorid || !email || !name || !password) {
      return res.status(400).json({ error: "Some fields are missing." });
    }

    // Check if utorid or email already exists
    const existing = await prisma.user.findFirst({
      where: { OR: [{ utorid }, { email }] },
    });
    if (existing) {
      return res.status(409).json({ error: "User exists already." });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user in DB
    const newUser = await prisma.user.create({
      data: {
        utorid,
        email,
        name,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      id: newUser.id,
      utorid: newUser.utorid,
      name: newUser.name,
      email: newUser.email,
      verified: newUser.verified ?? false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: " server error" });
  }
});


const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});