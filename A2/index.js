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
require('dotenv').config();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.warn(" JWT_SECRET is not set");
} else {
    console.log(" JWT_SECRET loaded.");
}

// ADD YOUR WORK HERE
const authRoutes = require('./src/routes/authRoutes');
const userRoutes = require('./src/routes/userRoutes');
const transactionsRoutes = require('./src/routes/transactionsRoutes');
const eventsRoutes = require('./src/routes/eventsRoutes');
const promotionsRoutes = require('./routes/promotionsRoutes');



app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/transactions', transactionsRoutes);
app.use('/events', eventsRoutes);
app.use('/promotions', promotionsRoutes); 


const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});
