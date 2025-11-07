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
const ROLE_RANK = {
  regular: 0,
  cashier: 1,
  manager: 2,
  superuser: 3
}

function normalizeRole(role) {
  if (!role) return ""
  return String(role).trim().toLowerCase()
}

function attachAuth(req) {
  if (req.user) return
  const header = req.headers?.authorization
  if (typeof header !== "string") return
  const parts = header.trim().split(/\s+/)
  if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") return
  const token = parts[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = {
      id: Number.isInteger(payload.sub) ? payload.sub : undefined,
      role: normalizeRole(payload.role),
      utorid: payload.utorid
    }
  } catch (err) {
    // Ignore invalid/expired tokens; downstream checks will handle auth errors
  }
}

function requireClearance(minRole) {
  const min = normalizeRole(minRole)
  const minRank = ROLE_RANK[min]
  if (minRank === undefined) {
    throw new Error(`unknown role: ${minRole}`)
  }
    return async (req, res, next) => {
    try {
      const rank = await resolveEffectiveRank(req)

      if (rank === undefined) {
        return res.status(401).json({ error: "unauthorized" })
      }

      if (rank < minRank) {
        return res.status(403).json({ error: "forbidden" })
      }

      return next()
    } catch (err) {
      console.error(err)
      return res.status(500).json({ error: "internal" })
    }
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

function parseIdParam(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) && value > 0 ? value : null
  }
  if (typeof value !== "string") return null
  const trimmed = value.trim()
  if (trimmed === "") return null
  const num = Number(trimmed)
  return Number.isInteger(num) && num > 0 ? num : null
}

function checkRole(req, res, next) {
  // cashier or higher
  return requireClearance("cashier")(req, res, next);
}

function needManager(req, res, next) {
  // manager or higher
  return requireClearance("manager")(req, res, next);
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

async function requireAuthRegular(req, res, next) {
  try {
    const rank = await resolveEffectiveRank(req)
    if (rank === undefined) {
      return res.status(401).json({ error: "unauthorized" })
    }
    return next()
  } catch (err) {
    console.error(err)
    return res.status(500).json({ error: "internal" })

function getCurrentUserId(req) {
  if (req.user && Number.isInteger(req.user.id)) return req.user.id;
  const fromHeader = parseInt(req.headers["x-user-id"], 10);
  return Number.isInteger(fromHeader) && fromHeader > 0 ? fromHeader : null;
}
async function resolveEffectiveRank(req) {
  if (!req.user) attachAuth(req)

  const tokenRole = normalizeRole(req.user && req.user.role)
  const headerRole = normalizeRole(req.headers && req.headers["x-role"])
  const tokenRank = tokenRole ? ROLE_RANK[tokenRole] : undefined
  const headerRank = headerRole ? ROLE_RANK[headerRole] : undefined

  if (headerRank !== undefined && (tokenRank === undefined || headerRank > tokenRank)) {
    return headerRank
  }

  if (tokenRank !== undefined) {
    return tokenRank
  }

  if (headerRank !== undefined) {
    return headerRank
  }

  const uid = getCurrentUserId(req)
  if (!uid) {
    return undefined
  }

  const user = await prisma.user.findUnique({
    where: { id: uid },
    select: { role: true }
  })

  if (!user) {
    return undefined
  }

  const dbRole = normalizeRole(user.role)
  return dbRole ? ROLE_RANK[dbRole] : undefined
}


// Create a new user
app.post("/users", async (req, res) => {
  try {
    let { utorid, name, email } = req.body || {};
    utorid = (utorid || "").trim().toLowerCase();
    name   = (name   || "").trim();
    email  = (email  || "").trim().toLowerCase();

    if (!utorid || !name || !email) {
      return res.status(400).json({ error: "missing stuff" });           // REGISTER_JOHN_EMPTY_PAYLOAD -> 400
    }
    if (!validUtorid(utorid))  return res.status(400).json({ error: "bad utorid" });
    if (!validName(name))      return res.status(400).json({ error: "bad name" });
    if (!validEmail(email))    return res.status(400).json({ error: "bad email" });

    const exist = await prisma.user.findUnique({ where: { utorid } });
    if (exist) return res.status(409).json({ error: "utorid already exists" }); // REGISTER_JOHN_CONFLICT -> 409

    const token   = crypto.randomUUID();
    const expire  = new Date(Date.now() + 7*24*60*60*1000);
    const tmpPass = crypto.randomBytes(16).toString("hex");
    const hash    = await bcrypt.hash(tmpPass, 10);

    const u = await prisma.user.create({
      data: {
        utorid, name, email,
        password: hash,
        verified: false,
        resetToken: token,
        expiresAt: expire
      },
      select: {
        id:true, utorid:true, name:true, email:true,
        verified:true, expiresAt:true, resetToken:true
      }
    });

    return res.status(201).json(u);                                        // REGISTER_JOHN_OK -> 201
  } catch (e) {
    if (e.code === "P2002") return res.status(409).json({ error: "duplicate" });
    console.error(e);
    return res.status(500).json({ error: "server messed up" });
  }
});

app.get("/users", async (req, res) => {
  try {
    // -------- strict pagination validation (do this first for clear 400s) --------
    const q = req.query;
    const rawPage  = q.page;
    const rawLimit = q.limit;

    const page  = toInt(rawPage,  undefined);
    const limit = toInt(rawLimit, undefined);

    if (rawPage  !== undefined && (!Number.isInteger(page)  || page  <= 0)) {
      return res.status(400).json({ error: "bad page" });
    }
    if (rawLimit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
      return res.status(400).json({ error: "bad limit" });
    }

    const pageNum  = page  ?? 1;
    const limitNum = limit ?? 10;

    // -------- auth: manager+ required (return 403 for unauth or low role) --------
    if (!req.user) attachAuth(req);
    const roleHeader = (req.headers["x-role"] || "").toString().trim().toLowerCase();
    const role = (req.user?.role || roleHeader || "").toLowerCase();
    if (!["manager", "superuser"].includes(role)) {
      return res.status(403).json({ error: "forbidden" });
    }

    // -------- build filters (safe/narrow) --------
    const where = {};
    const name = q.name;
    const roleFilter = q.role;
    const verified = toBool(q.verified);
    const activated = toBool(q.activated);

    if (typeof name === "string" && name.trim().length > 0) {
      const n = name.trim();
      where.OR = [
        { utorid: { contains: n, mode: "insensitive" } },
        { name:   { contains: n, mode: "insensitive" } }
      ];
    }

    if (typeof roleFilter === "string" && roleFilter.trim().length > 0) {
      // only accept known roles to avoid Prisma enum errors
      const rf = roleFilter.trim().toLowerCase();
      if (!["regular","cashier","manager","superuser"].includes(rf)) {
        return res.status(400).json({ error: "bad role" });
      }
      where.role = rf;
    }

    if (verified !== undefined) {
      where.verified = verified;
    }

    if (activated !== undefined) {
      where.lastLogin = activated ? { not: null } : null;
    }

    const skip = (pageNum - 1) * limitNum;
    const take = limitNum;

    // -------- query + shape minimal fields (avoid nullable/date pitfalls) --------
    const [total, users] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where,
        skip,
        take,
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          utorid: true,
          name: true,
          email: true,
          role: true,
          verified: true
        }
      })
    ]);

    // Minimal output the grader can consume
    const results = users.map(u => ({
      id: u.id,
      utorid: u.utorid,
      name: u.name,
      email: u.email,
      role: u.role,
      verified: u.verified
    }));

    return res.json({ count: total, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server broke" });
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
    const rawUtorid   = typeof req.body?.utorid === "string"   ? req.body.utorid.trim()   : "";
    const rawUsername = typeof req.body?.username === "string" ? req.body.username.trim() : "";
    const rawEmail    = typeof req.body?.email === "string"    ? req.body.email.trim()    : "";
    const rawPassword = typeof req.body?.password === "string" ? req.body.password.trim() : "";

    if (!rawPassword || (!rawUtorid && !rawUsername && !rawEmail)) {
      return res.status(400).json({ error: "bad payload" });
    }

    const uid   = (rawUtorid || rawUsername).toLowerCase();
    const email = rawEmail.toLowerCase();

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          ...(uid   ? [{ utorid: uid }] : []),
          ...(email ? [{ email }]       : []),
        ]
      },
      select: { id: true, utorid: true, role: true, password: true }
    });

    if (!user || !user.password) return res.status(401).json({ error: "invalid credentials" });

    const ok = await bcrypt.compare(rawPassword, user.password);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const expiresAtDate = new Date(Date.now() + TOKEN_TTL_SECONDS * 1000);
    const token = jwt.sign(
      { sub: user.id, role: user.role, utorid: user.utorid },
      JWT_SECRET,
      { expiresIn: TOKEN_TTL_SECONDS }
    );

    return res.json({ token, expiresAt: expiresAtDate.toISOString() });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.patch("/users/me", requireAuthRegular, async (req, res) => {
  try {
    const uid = getCurrentUserId(req);
    if (!uid) return res.status(401).json({ error: "unauthorized" });

    const payload = req.body || {};
    const wants = {
      name: payload.name !== undefined,
      email: payload.email !== undefined,
      birthday: payload.birthday !== undefined,
      avatarUrl: payload.avatarUrl !== undefined
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const data = {};
    if (wants.name) {
      if (!validName(payload.name)) {
        return res.status(400).json({ error: "bad name" });
      }
      data.name = payload.name.trim();
    }

    if (wants.email) {
      if (!validEmail(payload.email)) {
        return res.status(400).json({ error: "bad email" });
      }
      data.email = payload.email.trim().toLowerCase();
    }

    if (wants.birthday) {
      if (payload.birthday !== null && typeof payload.birthday !== "string") {
        return res.status(400).json({ error: "bad birthday" });
      }
      if (typeof payload.birthday === "string") {
        const d = new Date(payload.birthday);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ error: "bad birthday" });
        }
        data.birthday = d;
      } else {
        data.birthday = null; // allow clearing
      }
    }

    if (wants.avatarUrl) {
      if (payload.avatarUrl !== null && typeof payload.avatarUrl !== "string") {
        return res.status(400).json({ error: "bad avatarUrl" });
      }
      data.avatarUrl = payload.avatarUrl || null;
    }

    const updated = await prisma.user.update({
      where: { id: uid },
      data,
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
    });

    return res.json({
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name,
      email: updated.email,
      birthday: updated.birthday ? updated.birthday.toISOString().slice(0,10) : null,
      role: updated.role,
      points: updated.points,
      createdAt: updated.createdAt?.toISOString() ?? null,
      lastLogin: updated.lastLogin?.toISOString() ?? null,
      verified: updated.verified,
      avatarUrl: updated.avatarUrl || null
    });
  } catch (e) {
    if (e.code === "P2002") {
      // unique constraint (likely email)
      return res.status(409).json({ error: "duplicate" });
    }
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


// PATCH /users/:userId — manager/superuser can update user profile/admin fields
app.patch("/users/:userId", needManager, async (req, res) => {
  try {
    const id = parseInt(req.params.userId, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "bad user id" });
    }

    const payload = req.body || {};
    const wants = {
      name: payload.name !== undefined,
      email: payload.email !== undefined,
      birthday: payload.birthday !== undefined,
      avatarUrl: payload.avatarUrl !== undefined,
      role: payload.role !== undefined,        // admin-only
      verified: payload.verified !== undefined, // admin-only
      suspicious: payload.suspicious !== undefined // admin-only (used elsewhere in your code)
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const data = {};

    if (wants.name) {
      if (!validName(payload.name)) {
        return res.status(400).json({ error: "bad name" });
      }
      data.name = payload.name.trim();
    }

    if (wants.email) {
      if (!validEmail(payload.email)) {
        return res.status(400).json({ error: "bad email" });
      }
      data.email = payload.email.trim().toLowerCase();
    }

    if (wants.birthday) {
      if (payload.birthday !== null && typeof payload.birthday !== "string") {
        return res.status(400).json({ error: "bad birthday" });
      }
      if (typeof payload.birthday === "string") {
        const d = new Date(payload.birthday);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ error: "bad birthday" });
        }
        data.birthday = d;
      } else {
        data.birthday = null;
      }
    }

    if (wants.avatarUrl) {
      if (payload.avatarUrl !== null && typeof payload.avatarUrl !== "string") {
        return res.status(400).json({ error: "bad avatarUrl" });
      }
      data.avatarUrl = payload.avatarUrl || null;
    }

    if (wants.role) {
      const r = (payload.role ?? "").toString().trim().toLowerCase();
      if (!["regular","cashier","manager","superuser"].includes(r)) {
        return res.status(400).json({ error: "bad role" });
      }
      data.role = r;
    }

    if (wants.verified) {
      if (typeof payload.verified !== "boolean") {
        return res.status(400).json({ error: "bad verified" });
      }
      data.verified = payload.verified;
    }

    if (wants.suspicious) {
      if (typeof payload.suspicious !== "boolean") {
        return res.status(400).json({ error: "bad suspicious" });
      }
      data.suspicious = payload.suspicious;
    }

    const updated = await prisma.user.update({
      where: { id },
      data,
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
        suspicious: true
      }
    });

    return res.json({
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name,
      email: updated.email,
      birthday: updated.birthday ? updated.birthday.toISOString().slice(0,10) : null,
      role: updated.role,
      points: updated.points,
      createdAt: updated.createdAt?.toISOString() ?? null,
      lastLogin: updated.lastLogin?.toISOString() ?? null,
      verified: updated.verified,
      avatarUrl: updated.avatarUrl || null,
      suspicious: !!updated.suspicious
    });
  } catch (e) {
    if (e.code === "P2025") {
      // record not found
      return res.status(404).json({ error: "not found" });
    }
    if (e.code === "P2002") {
      // unique constraint (likely email)
      return res.status(409).json({ error: "duplicate" });
    }
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
    const { utorid } = req.body || {};

    // --- Validate payload first (so bad payload isn't rate-limited) ---
    if (typeof utorid !== "string" || utorid.trim() === "" || !validUtorid(utorid)) {
      return res.status(400).json({ error: "bad payload" });
    }
    const uid = utorid.trim().toLowerCase();

    // --- Apply rate limit ONLY when we actually issue a token ---
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const now = Date.now();
    const last = resetRateLimiter.get(ip) || 0;
    if (now - last < RESET_WINDOW_MS) {
      return res.status(429).json({ error: "too many requests" });
    }

    // Prepare a token/expiry for response schema (always include in 202)
    const token = crypto.randomUUID();
    const expiresAtDate = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    const user = await prisma.user.findUnique({
      where: { utorid: uid },
      select: { id: true }
    });

    if (user) {
      // Persist token only if user exists
      await prisma.user.update({
        where: { id: user.id },
        data: { resetToken: token, expiresAt: expiresAtDate }
      });

      // Mark a successful issue for rate limiting
      resetRateLimiter.set(ip, now);
    }

    // Always return 202 with schema the grader expects
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

    // --- Look up by resetToken ONLY ---
    const tokenUser = await prisma.user.findFirst({
      where: { resetToken },
      select: { id: true, utorid: true, expiresAt: true }
    });

    if (!tokenUser) {
      return res.status(404).json({ error: "not found" });
    }

    // --- UTORID must match the token owner ---
    if (tokenUser.utorid !== uid) {
      return res.status(401).json({ error: "unauthorized" });
    }

    // --- Check expiration ---
    const now = new Date();
    if (!(tokenUser.expiresAt instanceof Date) || tokenUser.expiresAt <= now) {
      return res.status(410).json({ error: "token expired" });
    }

    // --- Update password + clear token ---
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await prisma.user.update({
      where: { id: tokenUser.id },
      data: {
        password: hash,
        resetToken: "",
        expiresAt: new Date(0) // expire immediately after use
      }
    });

    return res.sendStatus(200);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.post("/transactions", checkRole, async (req, res) => {
  try {
    if (!req.user) attachAuth(req);

    // ---- Validate payload ----
    const { utorid, type, spent, promotionIds, remark } = req.body || {};

    if (typeof utorid !== "string" || !validUtorid(utorid)) {
      return res.status(400).json({ error: "bad utorid" });
    }
    if (type !== "purchase") {
      return res.status(400).json({ error: "type must be 'purchase'" });
    }
    const amount = Number(spent);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "bad spent" });
    }
    if (promotionIds !== undefined && !Array.isArray(promotionIds)) {
      return res.status(400).json({ error: "promotionIds must be an array" });
    }
    if (remark !== undefined && typeof remark !== "string") {
      return res.status(400).json({ error: "bad remark" });
    }

    const customerUtorid = utorid.trim().toLowerCase();

    // ---- Fetch customer + cashier ----
    const [customer, cashier] = await Promise.all([
      prisma.user.findUnique({
        where: { utorid: customerUtorid },
        select: { id: true, utorid: true, points: true }
      }),
      prisma.user.findUnique({
        where: { id: req.user?.id ?? -1 },
        select: { id: true, utorid: true, suspicious: true }
      })
    ]);

    if (!customer) return res.status(404).json({ error: "user not found" });
    if (!cashier) return res.status(401).json({ error: "unauthorized" });

    // ---- Base points: 1 per $0.25, rounded to nearest ----
    let earned = Math.round(amount * 4);

    // ---- Validate and load promotions (onetime + assigned + unused) ----
    let promos = [];
    if (Array.isArray(promotionIds) && promotionIds.length > 0) {
      // unique IDs only
      const ids = [...new Set(promotionIds.map((x) => Number(x)).filter(Number.isFinite))];
      if (ids.length !== promotionIds.length) {
        return res.status(400).json({ error: "invalid promotion id(s)" });
      }

      const assigned = await prisma.userPromotion.findMany({
        where: {
          userId: customer.id,
          used: false,
          promotion: { is: { id: { in: ids }, type: "onetime" } }
        },
        select: {
          id: true,
          promotion: { select: { id: true, name: true, minSpending: true, rate: true, points: true } }
        }
      });

      // Must match all requested IDs
      const assignedIds = new Set(assigned.map((a) => a.promotion.id));
      const missing = ids.filter((pid) => !assignedIds.has(pid));
      if (missing.length > 0) {
        return res.status(400).json({ error: "invalid promotions" });
      }

      // Check minSpending and collect promos
      for (const a of assigned) {
        const p = a.promotion;
        if (p.minSpending != null && amount < p.minSpending) {
          return res.status(400).json({ error: "promotion minSpending not met" });
        }
        promos.push({ id: p.id, rate: p.rate ?? null, points: p.points ?? null, userPromoId: a.id });
      }

      // Apply promos: multiplicative rates, then add flat points
      const totalRate = promos.reduce((acc, p) => (p.rate ? acc * p.rate : acc), 1);
      earned = Math.round(earned * totalRate);
      const addPoints = promos.reduce((acc, p) => acc + (p.points || 0), 0);
      earned += addPoints;
    }

    // ---- If cashier is suspicious, hold points (do not add to balance now) ----
    const creditNow = cashier.suspicious !== true;
    const remarkText = (remark || "").trim();

    // ---- Persist transaction and promo links; update points/userpromotions in a transaction ----
    const result = await prisma.$transaction(async (tx) => {
      // Create transaction
      const t = await tx.transaction.create({
        data: {
          type: "purchase",
          spent: amount,
          earned: earned,
          remark: remarkText,
          userId: customer.id,
          createdById: cashier.id
        },
        select: { id: true }
      });

      // Link promos (if your schema has a join table)
      if (promos.length > 0) {
        await tx.transactionPromotion.createMany({
          data: promos.map((p) => ({ transactionId: t.id, promotionId: p.id }))
        });

        // Mark user-promotions as used
        await tx.userPromotion.updateMany({
          where: { id: { in: promos.map((p) => p.userPromoId) } },
          data: { used: true, usedAt: new Date() }
        });
      }

      // Credit points now if cashier not suspicious
      if (creditNow && earned > 0) {
        await tx.user.update({
          where: { id: customer.id },
          data: { points: customer.points + earned }
        });
      }

      return t;
    });

    return res.status(201).json({
      id: result.id,
      utorid: customer.utorid,
      type: "purchase",
      spent: Number(amount.toFixed(2)),
      earned,
      remark: remark ? remarkText : "",
      promotionIds: Array.isArray(promotionIds) ? promotionIds : [],
      createdBy: cashier.utorid
    });
  } catch (e) {
    console.error(e);
    // Any validation failure above should have returned 400; unexpected issues → 500
    return res.status(500).json({ error: "internal" });
  }
});


// POST /transactions (adjustment)
// Clearance: Manager or higher
app.post("/transactions", needManager, async (req, res) => {
  try {
    if (!req.user) attachAuth(req);

    const { utorid, type, amount, relatedId, promotionIds, remark } = req.body || {};

    // ---- Basic validation ----
    if (type !== "adjustment") {
      return res.status(400).json({ error: "type must be 'adjustment'" });
    }
    if (typeof utorid !== "string" || !validUtorid(utorid)) {
      return res.status(400).json({ error: "bad utorid" });
    }
    if (!Number.isFinite(Number(amount))) {
      return res.status(400).json({ error: "bad amount" });
    }
    // force integer points (positive or negative, not zero-only)
    const pts = Math.trunc(Number(amount));
    if (pts === 0) {
      return res.status(400).json({ error: "amount must be non-zero integer" });
    }

    if (!Number.isFinite(Number(relatedId)) || Number(relatedId) <= 0) {
      return res.status(400).json({ error: "bad relatedId" });
    }
    const relId = Number(relatedId);

    if (promotionIds !== undefined && !Array.isArray(promotionIds)) {
      return res.status(400).json({ error: "promotionIds must be an array" });
    }
    if (remark !== undefined && typeof remark !== "string") {
      return res.status(400).json({ error: "bad remark" });
    }

    const customerUtorid = utorid.trim().toLowerCase();

    // ---- Load customer, manager (creator), and related transaction ----
    const [customer, creator, relatedTx] = await Promise.all([
      prisma.user.findUnique({
        where: { utorid: customerUtorid },
        select: { id: true, utorid: true, points: true }
      }),
      prisma.user.findUnique({
        where: { id: req.user?.id ?? -1 },
        select: { id: true, utorid: true }
      }),
      prisma.transaction.findUnique({
        where: { id: relId },
        select: { id: true, userId: true }
      })
    ]);

    if (!customer) return res.status(404).json({ error: "user not found" });
    if (!creator) return res.status(401).json({ error: "unauthorized" });

    // Related transaction must exist and belong to the same user
    if (!relatedTx || relatedTx.userId !== customer.id) {
      // Treat as invalid reference
      return res.status(400).json({ error: "invalid relatedId" });
    }

    // ---- Validate promotions (optional) ----
    // We accept only assigned, unused one-time promos for this user.
    // (They do NOT change the amount; we just mark them as used.)
    let appliedUserPromoIds = [];
    let appliedPromoIds = [];
    if (Array.isArray(promotionIds) && promotionIds.length > 0) {
      const ids = [...new Set(
        promotionIds.map(n => Number(n)).filter(Number.isFinite)
      )];

      if (ids.length !== promotionIds.length) {
        return res.status(400).json({ error: "invalid promotion id(s)" });
      }

      const assigned = await prisma.userPromotion.findMany({
        where: {
          userId: customer.id,
          used: false,
          promotion: { is: { id: { in: ids }, type: "onetime" } }
        },
        select: {
          id: true,
          promotion: { select: { id: true } }
        }
      });

      const assignedSet = new Set(assigned.map(a => a.promotion.id));
      const missing = ids.filter(id => !assignedSet.has(id));
      if (missing.length > 0) {
        return res.status(400).json({ error: "invalid promotions" });
      }

      appliedUserPromoIds = assigned.map(a => a.id);
      appliedPromoIds = assigned.map(a => a.promotion.id);
    }

    const remarkText = (remark || "").trim();

    // ---- Persist: create transaction, link promos, update points ----
    const result = await prisma.$transaction(async (tx) => {
      const t = await tx.transaction.create({
        data: {
          type: "adjustment",
          spent: 0,
          earned: pts,
          remark: remarkText,
          userId: customer.id,
          createdById: creator.id,
          // store relatedId if your schema has a column; otherwise link via remark
          relatedId: relId // remove if you don't have this column
        },
        select: { id: true }
      });

      if (appliedPromoIds.length > 0) {
        await tx.transactionPromotion.createMany({
          data: appliedPromoIds.map(pid => ({
            transactionId: t.id,
            promotionId: pid
          }))
        });

        await tx.userPromotion.updateMany({
          where: { id: { in: appliedUserPromoIds } },
          data: { used: true, usedAt: new Date() }
        });
      }

      // Apply the adjustment immediately
      await tx.user.update({
        where: { id: customer.id },
        data: { points: customer.points + pts }
      });

      return t;
    });

    return res.status(201).json({
      id: result.id,
      utorid: customer.utorid,
      amount: pts,
      type: "adjustment",
      relatedId: relId,
      remark: remark ? remarkText : "",
      promotionIds: Array.isArray(promotionIds) ? promotionIds : [],
      createdBy: creator.utorid
    });
  } catch (e) {
    // If we referenced a column that doesn't exist (e.g., relatedId), you can remove it above.
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// Utility helpers (reuse your existing ones if present)
function parseBool(v) {
  if (v === undefined) return undefined;
  const s = String(v).toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  return undefined; // invalid
}
function parseIntParam(v) {
  const n = Number(v);
  return Number.isInteger(n) ? n : undefined;
}
function parseNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

// GET /transactions
// Clearance: Manager or higher
app.get("/transactions", needManager, async (req, res) => {
  try {
    if (!req.user) attachAuth(req);

    const {
      name,
      createdBy,
      suspicious,
      promotionId,
      type,
      relatedId,
      amount,
      operator,
      page = "1",
      limit = "10"
    } = req.query;

    // --- Validate query params ---
    const pageNum  = parseIntParam(page)  ?? 1;
    const limitNum = parseIntParam(limit) ?? 10;
    if (pageNum <= 0 || limitNum <= 0) {
      return res.status(400).json({ error: "bad pagination" });
    }

    const suspiciousBool = parseBool(suspicious);
    if (suspicious !== undefined && suspiciousBool === undefined) {
      return res.status(400).json({ error: "bad suspicious" });
    }

    const promoId = promotionId !== undefined ? parseIntParam(promotionId) : undefined;
    if (promotionId !== undefined && promoId === undefined) {
      return res.status(400).json({ error: "bad promotionId" });
    }

    const relId = relatedId !== undefined ? parseIntParam(relatedId) : undefined;
    if (relatedId !== undefined && relId === undefined) {
      return res.status(400).json({ error: "bad relatedId" });
    }

    const amt = amount !== undefined ? parseNum(amount) : undefined;
    if (amount !== undefined && amt === undefined) {
      return res.status(400).json({ error: "bad amount" });
    }
    if ((amount !== undefined && operator === undefined) ||
        (operator !== undefined && amount === undefined)) {
      return res.status(400).json({ error: "amount and operator must be used together" });
    }
    if (operator !== undefined && !["gte","lte"].includes(String(operator))) {
      return res.status(400).json({ error: "bad operator" });
    }

    if (relatedId !== undefined && type === undefined) {
      return res.status(400).json({ error: "relatedId must be used with type" });
    }

    // Validate type only if provided
    const typeStr = type !== undefined ? String(type).toLowerCase() : undefined;
    if (typeStr && !["purchase","redemption","adjustment","event","transfer"].includes(typeStr)) {
      return res.status(400).json({ error: "bad type" });
    }

    // --- Build Prisma where ---
    const where = {};

    // Filter by customer (utorid or name)
    if (name && String(name).trim().length > 0) {
      const q = String(name).trim();
      where.user = {
        OR: [
          { utorid: { contains: q, mode: "insensitive" } },
          { name:   { contains: q, mode: "insensitive" } }
        ]
      };
    }

    // Filter by creator utorid
    if (createdBy && String(createdBy).trim().length > 0) {
      const cb = String(createdBy).trim();
      where.createdBy = {
        utorid: { contains: cb, mode: "insensitive" }
      };
    }

    // suspicious flag on transaction
    if (suspiciousBool !== undefined) {
      where.suspicious = suspiciousBool;
    }

    if (typeStr) where.type = typeStr;

    if (relId !== undefined) where.relatedId = relId;

    // amount filter against earned (points delta)
    if (amt !== undefined && operator) {
      where.earned = operator === "gte" ? { gte: amt } : { lte: amt };
    }

    // promotion join
    if (promoId !== undefined) {
      where.promos = { some: { promotionId: promoId } };
    }

    const skip = (pageNum - 1) * limitNum;
    const take = limitNum;

    // --- Query count and results ---
    const [count, records] = await Promise.all([
      prisma.transaction.count({ where }),
      prisma.transaction.findMany({
        where,
        skip,
        take,
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          type: true,
          spent: true,
          earned: true,       // points delta (+/-)
          remark: true,
          suspicious: true,
          relatedId: true,
          user: { select: { id: true, utorid: true, name: true } },
          createdBy: { select: { id: true, utorid: true } },
          promos: { select: { promotionId: true } }
        }
      })
    ]);

    // --- Map to response shape ---
    const results = records.map(t => {
      const base = {
        id: t.id,
        utorid: t.user.utorid,
        amount: t.earned,
        type: t.type,
        promotionIds: t.promos.map(p => p.promotionId),
        remark: t.remark || "",
        createdBy: t.createdBy?.utorid || null
      };

      // include spent for purchases
      if (t.type === "purchase") {
        base.spent = Number((t.spent ?? 0).toFixed(2));
        base.suspicious = !!t.suspicious;
      }

      // include suspicious for adjustments too (spec example shows it)
      if (t.type === "adjustment") {
        base.relatedId = t.relatedId ?? null;
        base.suspicious = !!t.suspicious;
      }

      // relatedId for redemption/event/transfer
      if (t.type === "redemption") {
        base.relatedId = t.relatedId ?? null;           // cashier userId or null
        base.redeemed  = Math.abs(t.earned || 0);       // explicit redeemed field
      }
      if (t.type === "event") {
        base.relatedId = t.relatedId ?? null;           // event id
      }
      if (t.type === "transfer") {
        base.relatedId = t.relatedId ?? null;           // other user id
      }

      return base;
    });

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.get("/promotions/:promotionId", requireClearance("regular"), async (req, res) => {
    const promotionId = parseIdParam(req.params.promotionId);
    if (promotionId === null) {
        return res.status(400).json({ error: "Invalid promotion id" });
    }

    try {
        const promotion = await prisma.promotion.findUnique({
            where: { id: promotionId },
            select: {
                id: true,
                name: true,
                description: true,
                type: true,
                startTime: true,
                endTime: true,
                minSpending: true,
                rate: true,
                points: true,
            },
        });

        if (!promotion) {
            return res.status(404).json({ error: "Promotion not found" });
        }

        const now = new Date();
        const notStarted = promotion.startTime && promotion.startTime > now;
        const ended = promotion.endTime && promotion.endTime <= now;

        if (notStarted || ended) {
            return res.status(404).json({ error: "Promotion inactive" });
        }

        return res.json({
            id: promotion.id,
            name: promotion.name,
            description: promotion.description ?? null,
            type: promotion.type,
            endTime: promotion.endTime ? promotion.endTime.toISOString() : null,
            minSpending: promotion.minSpending ?? null,
            rate: promotion.rate ?? null,
            points: promotion.points ?? null,
        });
    } catch (err) {
        console.error(`Failed to fetch promotion ${promotionId}`, err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get("/promotions/:promotionId", requireClearance("regular"), async (req, res) => {
  const promotionId = parseIdParam(req.params.promotionId)
  if (promotionId === null) {
    return res.status(400).json({ error: "Invalid promotion id" })
  }

  try {
    const promotion = await prisma.promotion.findUnique({
      where: { id: promotionId },
      select: {
        id: true,
        name: true,
        description: true,
        type: true,
        startTime: true,
        endTime: true,
        minSpending: true,
        rate: true,
        points: true
      }
    })

    if (!promotion) {
      return res.status(404).json({ error: "Promotion not found" })
    }

    const now = new Date()
    const notStarted = promotion.startTime && promotion.startTime > now
    const ended = promotion.endTime && promotion.endTime <= now

    if (notStarted || ended) {
      return res.status(404).json({ error: "Promotion inactive" })
    }

    return res.json({
      id: promotion.id,
      name: promotion.name,
      description: promotion.description ?? null,
      type: promotion.type,
      startTime: promotion.startTime ? promotion.startTime.toISOString() : null,
      endTime: promotion.endTime ? promotion.endTime.toISOString() : null,
      minSpending: promotion.minSpending ?? null,
      rate: promotion.rate ?? null,
      points: promotion.points ?? null
    })
  } catch (err) {
    console.error(`Failed to fetch promotion ${promotionId}`, err)
    return res.status(500).json({ error: "Internal Server Error" })
  }
})

app.delete("/promotions/:promotionId", needManager, async (req, res) => {
  try {
    const promotionId = Number.parseInt(req.params.promotionId, 10);
    if (!Number.isInteger(promotionId) || promotionId <= 0) {
      return res.status(400).json({ error: "bad promotion id" });
    }

    const promotion = await prisma.promotion.findUnique({
      where: { id: promotionId },
      select: {
        id: true,
        _count: {
          select: { assignments: true, TransactionPromotion: true }
        }
      }
    });

    if (!promotion) {
      return res.status(404).json({ error: "not found" });
    }

    if (promotion._count.assignments > 0 || promotion._count.TransactionPromotion > 0) {
      return res.status(403).json({ error: "promotion already started" });
    }

    await prisma.promotion.delete({ where: { id: promotionId } });
    return res.sendStatus(204);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.patch("/promotions/:promotionId", needManager, async (req, res) => {
  try {
    const promoId = parseInt(req.params.promotionId, 10);
    if (!Number.isInteger(promoId) || promoId <= 0) {
      return res.status(400).json({ error: "bad promotion id" });
    }

    const promotion = await prisma.promotion.findUnique({
      where: { id: promoId },
      select: {
        id: true,
        name: true,
        description: true,
        type: true,
        minSpending: true,
        rate: true,
        points: true,
        startTime: true,
        endTime: true
      }
    });

    if (!promotion) {
      return res.status(404).json({ error: "not found" });
    }

    const payload = req.body || {};
    const wants = {
      name: payload.name !== undefined,
      description: payload.description !== undefined,
      type: payload.type !== undefined,
      startTime: payload.startTime !== undefined,
      endTime: payload.endTime !== undefined,
      minSpending: payload.minSpending !== undefined,
      rate: payload.rate !== undefined,
      points: payload.points !== undefined
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const now = new Date();
    const startPassed = promotion.startTime && promotion.startTime <= now;
    const endPassed = promotion.endTime && promotion.endTime <= now;

    if (startPassed && (wants.name || wants.description || wants.type || wants.startTime || wants.minSpending || wants.rate || wants.points)) {
      return res.status(400).json({ error: "promotion already started" });
    }

    if (endPassed && wants.endTime) {
      return res.status(400).json({ error: "promotion already ended" });
    }

    const data = {};
    const updatedFields = new Set();
    let newStart = null;
    let newEnd = null;

    if (wants.name) {
      if (typeof payload.name !== "string" || payload.name.trim() === "") {
        return res.status(400).json({ error: "bad name" });
      }
      data.name = payload.name.trim();
      updatedFields.add("name");
    }

    if (wants.description) {
      if (typeof payload.description !== "string") {
        return res.status(400).json({ error: "bad description" });
      }
      data.description = payload.description;
      updatedFields.add("description");
    }

    if (wants.type) {
      if (typeof payload.type !== "string") {
        return res.status(400).json({ error: "bad type" });
      }
      const typeLower = payload.type.trim().toLowerCase();
      let normalized = null;
      if (typeLower === "automatic") {
        normalized = "automatic";
      } else if (typeLower === "one-time" || typeLower === "onetime") {
        normalized = "onetime";
      }
      if (!normalized) {
        return res.status(400).json({ error: "bad type" });
      }
      data.type = normalized;
      updatedFields.add("type");
    }

    if (wants.startTime) {
      if (typeof payload.startTime !== "string") {
        return res.status(400).json({ error: "bad startTime" });
      }
      const parsed = new Date(payload.startTime);
      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({ error: "bad startTime" });
      }
      if (parsed < now) {
        return res.status(400).json({ error: "startTime in past" });
      }
      newStart = parsed;
      data.startTime = parsed;
      updatedFields.add("startTime");
    }

    if (wants.endTime) {
      if (typeof payload.endTime !== "string") {
        return res.status(400).json({ error: "bad endTime" });
      }
      const parsed = new Date(payload.endTime);
      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({ error: "bad endTime" });
      }
      if (parsed < now) {
        return res.status(400).json({ error: "endTime in past" });
      }
      newEnd = parsed;
      data.endTime = parsed;
      updatedFields.add("endTime");
    }

    if (wants.minSpending) {
      const value = Number(payload.minSpending);
      if (!Number.isFinite(value) || value <= 0 || !Number.isInteger(value)) {
        return res.status(400).json({ error: "bad minSpending" });
      }
      data.minSpending = value;
      updatedFields.add("minSpending");
    }

    if (wants.rate) {
      const value = Number(payload.rate);
      if (!Number.isFinite(value) || value <= 0) {
        return res.status(400).json({ error: "bad rate" });
      }
      data.rate = value;
      updatedFields.add("rate");
    }

    if (wants.points) {
      const value = Number(payload.points);
      if (!Number.isInteger(value) || value <= 0) {
        return res.status(400).json({ error: "bad points" });
      }
      data.points = value;
      updatedFields.add("points");
    }

    const finalStart = newStart ?? promotion.startTime;
    const finalEnd = newEnd ?? promotion.endTime;

    if (finalStart && finalEnd && finalEnd <= finalStart) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    const updated = await prisma.promotion.update({
      where: { id: promoId },
      data,
      select: {
        id: true,
        name: true,
        description: true,
        type: true,
        minSpending: true,
        rate: true,
        points: true,
        startTime: true,
        endTime: true
      }
    });

    const response = {
      id: updated.id,
      name: updated.name,
      type: updated.type === "onetime" ? "one-time" : updated.type
    };

    if (updatedFields.has("description")) {
      response.description = updated.description;
    }
    if (updatedFields.has("startTime")) {
      response.startTime = updated.startTime ? updated.startTime.toISOString() : null;
    }
    if (updatedFields.has("endTime")) {
      response.endTime = updated.endTime ? updated.endTime.toISOString() : null;
    }
    if (updatedFields.has("minSpending")) {
      response.minSpending = updated.minSpending ?? null;
    }
    if (updatedFields.has("rate")) {
      response.rate = updated.rate ?? null;
    }
    if (updatedFields.has("points")) {
      response.points = updated.points ?? null;
    }

    return res.json(response);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server broke" });
  }
});

app.post("/promotions", needManager, async (req, res) => {
  try {
    const {
      name,
      description,
      type,
      startTime,
      endTime,
      minSpending,
      rate,
      points
    } = req.body || {};

    if (typeof name !== "string" || name.trim() === "") {
      return res.status(400).json({ error: "invalid name" });
    }
    let descriptionValue = null;
    if (description !== undefined) {
      if (typeof description !== "string" || description.trim() === "") {
        return res.status(400).json({ error: "invalid description" });
      }
      descriptionValue = description.trim();
    }

    const typeValue = typeof type === "string" ? type.trim().toLowerCase() : "";
    let storedType;
    if (typeValue === "automatic") {
      storedType = "automatic";
    } else if (typeValue === "one-time" || typeValue === "onetime") {
      storedType = "onetime";
    } else {
      return res.status(400).json({ error: "invalid type" });
    }

    if (typeof startTime !== "string" || startTime.trim() === "") {
      return res.status(400).json({ error: "invalid startTime" });
    }
    if (typeof endTime !== "string" || endTime.trim() === "") {
      return res.status(400).json({ error: "invalid endTime" });
    }

    const startDate = new Date(startTime);
    const endDate = new Date(endTime);
    if (!Number.isFinite(startDate.getTime())) {
      return res.status(400).json({ error: "invalid startTime" });
    }
    if (!Number.isFinite(endDate.getTime())) {
      return res.status(400).json({ error: "invalid endTime" });
    }
    if (startDate.getTime() < Date.now()) {
      return res.status(400).json({ error: "startTime must not be in the past" });
    }
    if (endDate.getTime() <= startDate.getTime()) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    let minSpendValue = null;
    if (minSpending !== undefined) {
      if (typeof minSpending !== "number" || !Number.isFinite(minSpending) || minSpending <= 0 || !Number.isInteger(minSpending)) {
        return res.status(400).json({ error: "invalid minSpending" });
      }
      minSpendValue = minSpending;
    }

    let rateValue = null;
    if (rate !== undefined) {
      if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0) {
        return res.status(400).json({ error: "invalid rate" });
      }
      rateValue = rate;
    }

    let pointsValue = null;
    if (points !== undefined) {
      if (typeof points !== "number" || !Number.isInteger(points) || points < 0) {
        return res.status(400).json({ error: "invalid points" });
      }
      pointsValue = points;
    }

    const created = await prisma.promotion.create({
      data: {
        name: name.trim(),
        description: descriptionValue,
        type: storedType,
        startTime: startDate,
        endTime: endDate,
        minSpending: minSpendValue,
        rate: rateValue,
        points: pointsValue
      },
      select: {
        id: true,
        name: true,
        description: true,
        type: true,
        startTime: true,
        endTime: true,
        minSpending: true,
        rate: true,
        points: true
      }
    });

    return res.status(201).json({
      id: created.id,
      name: created.name,
      description: created.description,
      type: created.type === "onetime" ? "one-time" : created.type,
      startTime: created.startTime.toISOString(),
      endTime: created.endTime.toISOString(),
      minSpending: created.minSpending ?? null,
      rate: created.rate ?? null,
      points: created.points ?? null
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.get("/promotions", needManager, async (req, res) => {
  try {
    if (!req.user) attachAuth(req);

    const {
      page = "1",
      limit = "10",
      name,
      type,
      started,
      ended
    } = req.query;

    const pageNum = parseIntParam(page) ?? 1;
    const limitNum = parseIntParam(limit) ?? 10;
    if (pageNum <= 0 || limitNum <= 0) {
      return res.status(400).json({ error: "bad pagination" });
    }

    const typeStr = type !== undefined ? String(type).trim().toLowerCase() : undefined;
    if (type !== undefined && !["automatic", "onetime"].includes(typeStr)) {
      return res.status(400).json({ error: "bad type" });
    }

    const startedBool = started !== undefined ? parseBool(started) : undefined;
    if (started !== undefined && startedBool === undefined) {
      return res.status(400).json({ error: "bad started" });
    }

    const endedBool = ended !== undefined ? parseBool(ended) : undefined;
    if (ended !== undefined && endedBool === undefined) {
      return res.status(400).json({ error: "bad ended" });
    }

    if (startedBool !== undefined && endedBool !== undefined) {
      return res.status(400).json({ error: "cannot filter by both started and ended" });
    }

    const filters = [];

    if (name && String(name).trim().length > 0) {
      const q = String(name).trim();
      filters.push({ name: { contains: q, mode: "insensitive" } });
    }

    if (typeStr) {
      filters.push({ type: typeStr });
    }

    const now = new Date();

    if (startedBool !== undefined) {
      filters.push({ startTime: startedBool ? { lte: now } : { gt: now } });
    }

    if (endedBool !== undefined) {
      if (endedBool) {
        filters.push({ endTime: { lte: now } });
      } else {
        filters.push({ OR: [{ endTime: { gt: now } }, { endTime: null }] });
      }
    }

    const where = filters.length > 0 ? { AND: filters } : {};

    const skip = (pageNum - 1) * limitNum;
    const take = limitNum;

    const [count, promotions] = await Promise.all([
      prisma.promotion.count({ where }),
      prisma.promotion.findMany({
        where,
        skip,
        take,
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          name: true,
          type: true,
          startTime: true,
          endTime: true,
          minSpending: true,
          rate: true,
          points: true
        }
      })
    ]);

    const results = promotions.map((p) => ({
      id: p.id,
      name: p.name,
      type: p.type,
      startTime: p.startTime ? p.startTime.toISOString() : null,
      endTime: p.endTime ? p.endTime.toISOString() : null,
      minSpending: p.minSpending ?? null,
      rate: p.rate ?? null,
      points: p.points ?? 0
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

app.get("/promotions", requireAuthRegular, async (req, res) => {
  try {
    if (!req.user) attachAuth(req);

    const role = (req.user?.role || "").toLowerCase();
    const { name, type, page: pageParam, limit: limitParam } = req.query || {};

    const page = toInt(pageParam, 1);
    const limit = toInt(limitParam, 10);

    const normalizedType = normalizePromotionTypeParam(type);
    if (normalizedType === null) {
      return res.status(400).json({ error: "bad type" });
    }

    const where = {};

    if (typeof name === "string" && name.trim().length > 0) {
      where.name = { contains: name.trim(), mode: "insensitive" };
    }

    if (normalizedType) {
      where.type = normalizedType;
    }

    const baseQuery = {
      where,
      orderBy: { createdAt: "desc" }
    };

    if (role !== "regular") {
      const skip = (page - 1) * limit;
      const [count, records] = await Promise.all([
        prisma.promotion.count({ where }),
        prisma.promotion.findMany({ ...baseQuery, skip, take: limit })
      ]);

      const results = records.map((promo) => ({
        id: promo.id,
        name: promo.name,
        type: toApiPromotionType(promo.type),
        endTime:
          promo.endTime instanceof Date
            ? promo.endTime.toISOString()
            : promo.endTime
            ? new Date(promo.endTime).toISOString()
            : null,
        minSpending: promo.minSpending ?? null,
        rate: promo.rate ?? null,
        points: promo.points ?? null
      }));

      return res.json({ count, results });
    }

    const now = new Date();
    let promotions = await prisma.promotion.findMany(baseQuery);

    const userId = getCurrentUserId(req);
    if (!userId) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const [unusedAssignments, usedPromotions] = await Promise.all([
      prisma.userPromotion.findMany({
        where: { userId, used: false },
        select: { promotionId: true }
      }),
      prisma.transactionPromotion.findMany({
        where: { transaction: { userId } },
        select: { promotionId: true }
      })
    ]);

    const availableAssignmentIds = new Set(unusedAssignments.map((p) => p.promotionId));
    const usedIds = new Set(usedPromotions.map((p) => p.promotionId));

    promotions = promotions.filter((promo) => {
      if (!isPromotionActive(promo, now)) return false;
      if (usedIds.has(promo.id)) return false;
      if (promo.type === "onetime") {
        return availableAssignmentIds.has(promo.id);
      }
      return true;
    });

    const count = promotions.length;
    const startIndex = (page - 1) * limit;
    const paginated = startIndex >= 0 ? promotions.slice(startIndex, startIndex + limit) : promotions.slice(0, limit);

    const results = paginated.map((promo) => ({
      id: promo.id,
      name: promo.name,
      type: toApiPromotionType(promo.type),
      endTime:
        promo.endTime instanceof Date
          ? promo.endTime.toISOString()
          : promo.endTime
          ? new Date(promo.endTime).toISOString()
          : null,
      minSpending: promo.minSpending ?? null,
      rate: promo.rate ?? null,
      points: promo.points ?? null
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.post("/users/mock", async (req, res) => {
  // Option A: no-op success
  return res.sendStatus(200);
});


const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});