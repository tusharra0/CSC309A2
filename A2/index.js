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
const crypto = require("crypto");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const prisma = new PrismaClient();
const SALT_ROUNDS = 10;
const resetRateLimiter = new Map(); // ip -> lastTimestampMs
const RESET_WINDOW_MS = 60 * 1000;

const jwt = require("jsonwebtoken");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const TOKEN_TTL_SECONDS = parseInt(process.env.JWT_TTL_SECONDS || "7200", 10); 

function checkRole(req,res,next){
  const role = (req.headers["x-role"] || "").toLowerCase()
  if(role==="cashier" || role==="manager" || role==="superuser"){
    next()
  }else{
    res.status(403).json({error:"need cashier or higher"})
  }
}

function validUtorid(x){
  return /^[a-z0-9]{7,8}$/i.test(x)
}
function validName(x){
  return typeof x==="string" && x.trim().length>0 && x.trim().length<=50
}
function validEmail(x){
  return /^[^@\s]+@(?:mail\.)?utoronto\.ca$/i.test(x)
}

function needManager(req,res,next){
  const r = (req.headers["x-role"] || "").toLowerCase()
  if(r==="manager" || r==="superuser"){
    next()
  }else{
    res.status(403).json({error:"need manager or higher"})
  }
}

function toBool(v){
  if(v===undefined) return undefined
  const s = String(v).toLowerCase()
  if(s==="true") return true
  if(s==="false") return false
  return undefined
}

function toInt(v,def){
  const n = parseInt(v,10)
  if(Number.isFinite(n) && n>0) return n
  return def
}

function requireAuthRegular(req, res, next) {
  if (!req.user) attachAuth(req); 
  const role = (req.user && req.user.role) || "";
  if (!role) return res.status(401).json({ error: "unauthorized" }); 
  if (["regular", "cashier", "manager", "superuser"].includes(role)) return next();
  return res.status(403).json({ error: "forbidden" });
}

function getCurrentUserId(req) {
  if (req.user && Number.isInteger(req.user.id)) return req.user.id;
  const fromHeader = parseInt(req.headers["x-user-id"], 10);
  return Number.isInteger(fromHeader) && fromHeader > 0 ? fromHeader : null;
}


// Create a new user
app.post("/users", checkRole, async (req, res) => {
  try {
    let {utorid,name,email} = req.body || {}
    utorid = (utorid||"").trim().toLowerCase()
    name = (name||"").trim()
    email = (email||"").trim().toLowerCase()

    if(!utorid || !name || !email){
      return res.status(400).json({error:"missing stuff"})
    }
    if(!validUtorid(utorid)){
      return res.status(400).json({error:"bad utorid"})
    }
    if(!validName(name)){
      return res.status(400).json({error:"bad name"})
    }
    if(!validEmail(email)){
      return res.status(400).json({error:"bad email"})
    }

    const exist = await prisma.user.findUnique({where:{utorid}})
    if(exist){
      return res.status(409).json({error:"utorid already exists"})
    }

    const token = crypto.randomUUID()
    const expire = new Date(Date.now() + 7*24*60*60*1000)
    const tmpPass = crypto.randomBytes(16).toString("hex")
    const hash = await bcrypt.hash(tmpPass,10)

    const u = await prisma.user.create({
      data:{
        utorid,
        name,
        email,
        password:hash,
        verified:false,
        resetToken:token,
        expiresAt:expire
      },
      select:{
        id:true,
        utorid:true,
        name:true,
        email:true,
        verified:true,
        expiresAt:true,
        resetToken:true
      }
    })

    res.status(201).json(u)
  }catch(e){
    if(e.code==="P2002"){
      return res.status(409).json({error:"duplicate"})
    }
    console.error(e)
    res.status(500).json({error:"server messed up"})
  }
});


app.get("/users", needManager, async (req,res)=>{
  try{
    const q = req.query
    const name = q.name
    const role = q.role
    const verified = toBool(q.verified)
    const activated = toBool(q.activated)
    const page = toInt(q.page,1)
    const limit = toInt(q.limit,10)

    const where = {}

    if(name && String(name).trim().length>0){
      const n = String(name).trim()
      where.OR = [
        { utorid: { contains:n, mode:"insensitive" } },
        { name: { contains:n, mode:"insensitive" } }
      ]
    }

    if(role && String(role).trim().length>0){
      where.role = String(role).trim().toLowerCase()
    }

    if(verified!==undefined){
      where.verified = verified
    }

    if(activated!==undefined){
      if(activated){
        where.lastLogin = { not:null }
      }else{
        where.lastLogin = null
      }
    }

    const skip = (page-1)*limit
    const take = limit

    const total = await prisma.user.count({ where: where })

    const users = await prisma.user.findMany({
      where: where,
      skip: skip,
      take: take,
      orderBy: { createdAt: "desc" },
      select: {
        id:true,
        utorid:true,
        name:true,
        email:true,
        birthday:true,
        role:true,
        points:true,
        createdAt:true,
        lastLogin:true,
        verified:true,
        avatarUrl:true
      }
    })

    const results = users.map(u=>{
      return {
        id:u.id,
        utorid:u.utorid,
        name:u.name,
        email:u.email,
        birthday:u.birthday ? u.birthday.toISOString().slice(0,10) : null,
        role:u.role,
        points:u.points,
        createdAt:u.createdAt,
        lastLogin:u.lastLogin,
        verified:u.verified,
        avatarUrl:u.avatarUrl
      }
    })

    res.json({count:total, results:results})
  }catch(e){
    console.error(e)
    res.status(500).json({error:"server broke"})
  }
});

app.get("/users/:userId", checkRole, async (req,res)=>{
  try{
    const id = parseInt(req.params.userId,10)
    if(!Number.isInteger(id) || id<=0){
      return res.status(400).json({error:"bad user id"})
    }

    const user = await prisma.user.findUnique({
      where:{ id:id },
      select:{
        id:true,
        utorid:true,
        name:true,
        points:true,
        verified:true,
        promotions:{
          where:{
            used:false,
            promotion:{ type:"onetime" }
          },
          select:{
            promotion:{
              select:{
                id:true,
                name:true,
                minSpending:true,
                rate:true,
                points:true
              }
            }
          }
        }
      }
    })

    if(!user){
      return res.status(404).json({error:"not found"})
    }

    const promos = user.promotions.map(x=>({
      id:x.promotion.id,
      name:x.promotion.name,
      minSpending:x.promotion.minSpending,
      rate:x.promotion.rate,
      points:x.promotion.points
    }))

    const out = {
      id:user.id,
      utorid:user.utorid,
      name:user.name,
      points:user.points,
      verified:user.verified,
      promotions:promos
    }

    res.json(out)
  }catch(e){
    console.error(e)
    res.status(500).json({error:"server broke"})
  }
});




app.post("/auth/tokens", async (req, res) => {
  try {
    const { utorid, password } = req.body || {};

    // 400: invalid payload
    if (typeof utorid !== "string" || utorid.trim() === "" ||
        typeof password !== "string" || password === "") {
      return res.status(400).json({ error: "bad payload" });
    }

    const uid = utorid.trim().toLowerCase();

    // Look up user by utorid
    const user = await prisma.user.findUnique({
      where: { utorid: uid },
      select: { id: true, utorid: true, role: true, password: true }
    });

    // 401: wrong creds (don’t leak which part failed)
    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const expiresAtDate = new Date(Date.now() + TOKEN_TTL_SECONDS * 1000);
    const token = jwt.sign(
      { sub: user.id, role: user.role, utorid: user.utorid },
      JWT_SECRET,
      { expiresIn: TOKEN_TTL_SECONDS }
    );

    return res.json({
      token,
      expiresAt: expiresAtDate.toISOString()
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.get("/users/me", requireAuthRegular, async (req, res) => {
  try {
    const uid = getCurrentUserId(req);
    if (!uid) return res.status(401).json({ error: "unauthorized" });

    const user = await prisma.user.findUnique({
      where: { id: uid },
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
        avatarUrl: true,
        promotions: {
          where: { used: false, promotion: { is: { type: "onetime" } } },
          select: {
            promotion: {
              select: { id: true, name: true, minSpending: true, rate: true, points: true }
            }
          }
        }
      }
    });

    if (!user) return res.status(404).json({ error: "not found" });

    const promotions = user.promotions.map(x => ({
      id: x.promotion.id,
      name: x.promotion.name,
      minSpending: x.promotion.minSpending,
      rate: x.promotion.rate,
      points: x.promotion.points
    }));

    return res.json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      email: user.email,
      birthday: user.birthday ? user.birthday.toISOString().slice(0, 10) : null,
      role: user.role,
      points: user.points,
      createdAt: user.createdAt?.toISOString() ?? null,
      lastLogin: user.lastLogin?.toISOString() ?? null,
      verified: user.verified,
      avatarUrl: user.avatarUrl || null,
      promotions
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,20}$/;

// PATCH /users/me/password
app.patch("/users/me/password", requireAuthRegular, async (req, res) => {
  try {
    const { old, new: newPass } = req.body || {};
    const uid = getCurrentUserId(req);
    if (!uid) return res.status(401).json({ error: "unauthorized" });

    // --- Validate payload fields ---
    if (typeof old !== "string" || typeof newPass !== "string") {
      return res.status(400).json({ error: "bad payload" });
    }

    // --- Enforce password rules ---
    if (!PASSWORD_REGEX.test(newPass)) {
      return res.status(400).json({ error: "invalid new password" });
    }

    // --- Fetch current user ---
    const user = await prisma.user.findUnique({
      where: { id: uid },
      select: { password: true }
    });
    if (!user) return res.status(404).json({ error: "not found" });

    // --- Check old password ---
    const ok = await bcrypt.compare(old, user.password);
    if (!ok) return res.status(403).json({ error: "incorrect password" });

    // --- Hash and update ---
    const hash = await bcrypt.hash(newPass, SALT_ROUNDS);
    await prisma.user.update({
      where: { id: uid },
      data: { password: hash }
    });

    return res.sendStatus(200); // success
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.post("/auth/resets", async (req, res) => {
  try {
    // Rate limit by IP
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const now = Date.now();
    const last = resetRateLimiter.get(ip) || 0;
    if (now - last < RESET_WINDOW_MS) {
      return res.status(429).json({ error: "too many requests" });
    }
    resetRateLimiter.set(ip, now);

    const { utorid } = req.body || {};
    if (typeof utorid !== "string" || utorid.trim() === "" || !validUtorid(utorid)) {
      // Bad payload (invalid or missing utorid)
      return res.status(400).json({ error: "bad payload" });
    }

    const uid = utorid.trim().toLowerCase();
    const user = await prisma.user.findUnique({ where: { utorid: uid }, select: { id: true } });

    // Always return 202. If the user exists, issue a reset token that expires in 1 hour.
    if (!user) {
      // Do not leak whether the account exists.
      return res.status(202).json({});
    }

    const token = crypto.randomUUID();
    const expiresAtDate = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken: token, expiresAt: expiresAtDate }
    });

    return res.status(202).json({
      expiresAt: expiresAtDate.toISOString(),
      resetToken: token
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.post("/auth/resets/:resetToken", async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { utorid, password } = req.body || {};

    // --- Validate payload ---
    if (
      typeof utorid !== "string" ||
      utorid.trim() === "" ||
      typeof password !== "string" ||
      password.trim() === ""
    ) {
      return res.status(400).json({ error: "bad payload" });
    }
    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({ error: "invalid password" });
    }

    const uid = utorid.trim().toLowerCase();

    // --- Look up the user by utorid + token ---
    const user = await prisma.user.findFirst({
      where: { utorid: uid, resetToken },
      select: { id: true, expiresAt: true }
    });

    if (!user) {
      return res.status(404).json({ error: "not found" });
    }

    // --- Check expiration ---
    const now = new Date();
    if (user.expiresAt <= now) {
      return res.status(410).json({ error: "token expired" });
    }

    // --- Update password + clear token ---
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hash,
        resetToken: "",
        expiresAt: new Date(0) // expired immediately after use
      }
    });

    return res.sendStatus(200);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});



const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});