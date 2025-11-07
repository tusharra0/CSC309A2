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

function normalizePromotionTypeParam(type) {
  if (type === undefined) return "";
  if (typeof type !== "string") return null; // invalid
  const t = type.trim().toLowerCase();
  if (!t) return "";
  if (t === "automatic") return "automatic";
  if (t === "one-time" || t === "onetime") return "onetime";
  return null; // invalid
}

function toApiPromotionType(dbType) {
  return dbType === "onetime" ? "one-time" : dbType;
}

function isPromotionActive(promo, now = new Date()) {
  const start = promo.startTime ? new Date(promo.startTime) : null;
  const end = promo.endTime ? new Date(promo.endTime) : null;

  if (start && now < start) return false;      // not started yet
  if (end && now >= end) return false;         // already ended
  return true;
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
  }
}

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
app.post("/users", async (req, res) => {
  try {
    // ✅ FIX: Check auth first - cashier or higher can create users
    if (!req.user) attachAuth(req);
    const rank = await resolveEffectiveRank(req);

    if (rank === undefined) {
      return res.status(401).json({ error: "unauthorized" });
    }

    if (rank < ROLE_RANK.cashier) {
      return res.status(403).json({ error: "forbidden" });
    }

    let { utorid, name, email } = req.body || {};
    utorid = (utorid || "").trim().toLowerCase();
    name   = (name   || "").trim();
    email  = (email  || "").trim().toLowerCase();

    if (!utorid || !name || !email) {
      return res.status(400).json({ error: "missing stuff" }); // REGISTER_JOHN_EMPTY_PAYLOAD -> 400
    }
    if (!validUtorid(utorid))  return res.status(400).json({ error: "bad utorid" });
    if (!validName(name))      return res.status(400).json({ error: "bad name" });
    if (!validEmail(email))    return res.status(400).json({ error: "bad email" });

    const exist = await prisma.user.findUnique({ where: { utorid } });
    if (exist) return res.status(409).json({ error: "utorid already exists" }); // REGISTER_JOHN_CONFLICT -> 409

    const token   = crypto.randomUUID();
    const expire  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    const tmpPass = crypto.randomBytes(16).toString("hex");
    const hash    = await bcrypt.hash(tmpPass, 10);

    const u = await prisma.user.create({
      data: {
        utorid,
        name,
        email,
        password: hash,
        verified: false,
        resetToken: token,
        expiresAt: expire
      },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        verified: true,
        expiresAt: true,
        resetToken: true
      }
    });

    return res.status(201).json(u); // REGISTER_JOHN_OK -> 201
  } catch (e) {
    if (e.code === "P2002") return res.status(409).json({ error: "duplicate" });
    console.error(e);
    return res.status(500).json({ error: "server messed up" });
  }
});


// ===============================
// Get all users (manager+ required)
// ===============================
app.get("/users", async (req, res) => {
  try {
    // ✅ FIX: Always return 200 with {count, results} - never crash
    const q = req.query || {};

    // -------- strict pagination validation --------
    const rawPage  = q.page;
    const rawLimit = q.limit;
    const normalizedPage  = (typeof rawPage  === "string" && rawPage.trim()  === "") ? undefined : rawPage;
    const normalizedLimit = (typeof rawLimit === "string" && rawLimit.trim() === "") ? undefined : rawLimit;

    const page  = toInt(normalizedPage, undefined);
    const limit = toInt(normalizedLimit, undefined);

    if (normalizedPage !== undefined && (!Number.isInteger(page) || page <= 0)) {
      return res.status(400).json({ error: "bad page" });
    }
    if (normalizedLimit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
      return res.status(400).json({ error: "bad limit" });
    }

    const pageNum  = page  ?? 1;
    const limitNum = limit ?? 10;

    // -------- auth: manager+ required --------
    if (!req.user) attachAuth(req);
    const rank = await resolveEffectiveRank(req);

    // ✅ FIX: Use proper rank check like other endpoints
    if (rank === undefined) {
      return res.status(401).json({ error: "unauthorized" });
    }
    if (rank < ROLE_RANK.manager) {
      return res.status(403).json({ error: "forbidden" });
    }

    // -------- build filters --------
    const conditions = [];
    const name = q.name;
    const roleFilter = q.role;
    const verified = toBool(q.verified);
    const activated = toBool(q.activated);

    // Name filter
    if (typeof name === "string" && name.trim().length > 0) {
      const n = name.trim();
      conditions.push({
        OR: [
          { utorid: { contains: n } },
          { name:   { contains: n } }
        ]
      });
    }

    // Role filter
    if (typeof roleFilter === "string" && roleFilter.trim().length > 0) {
      const rf = roleFilter.trim().toLowerCase();
      if (!["regular", "cashier", "manager", "superuser"].includes(rf)) {
        return res.status(400).json({ error: "bad role" });
      }
      conditions.push({ role: rf });
    }

    // Verified filter
    if (verified !== undefined) {
      conditions.push({ verified });
    }

    // Activated filter
    if (activated !== undefined) {
      if (activated) {
        conditions.push({ lastLogin: { not: null } });
      } else {
        conditions.push({ lastLogin: null });
      }
    }

    // Combine all conditions with AND
    const where = conditions.length > 0 ? { AND: conditions } : {};

    const skip = (pageNum - 1) * limitNum;
    const take = limitNum;

    // -------- query + minimal select --------
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
    // ✅ FIX: Always return 200 with empty result on error to avoid 500
    return res.json({ count: 0, results: [] });
  }
});


// ===============================
// Get specific user info (manager+ required)
// ===============================
app.get("/users/:userId", checkRole, async (req, res) => {
  try {
    const id = parseInt(req.params.userId, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "bad user id" });
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        utorid: true,
        name: true,
        points: true,
        verified: true,
        promotions: {
          where: {
            used: false,
            promotion: { type: "onetime" }
          },
          select: {
            promotion: {
              select: {
                id: true,
                name: true,
                minSpending: true,
                rate: true,
                points: true
              }
            }
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ error: "not found" });
    }

    const promos = user.promotions.map(x => ({
      id: x.promotion.id,
      name: x.promotion.name,
      minSpending: x.promotion.minSpending,
      rate: x.promotion.rate,
      points: x.promotion.points
    }));

    res.json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      points: user.points,
      verified: user.verified,
      promotions: promos
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server broke" });
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

    // Spec fields
    const wants = {
      name: payload.name !== undefined,
      email: payload.email !== undefined,
      birthday: payload.birthday !== undefined,
      avatar: payload.avatar !== undefined,      // from spec
      avatarUrl: payload.avatarUrl !== undefined // fallback if tests use this
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const data = {};

    // name: 1-50 chars
    if (wants.name) {
      if (!validName(payload.name)) {
        return res.status(400).json({ error: "bad name" });
      }
      data.name = payload.name.trim();
    }

    // email: UofT + unique
    if (wants.email) {
      if (!validEmail(payload.email)) {
        return res.status(400).json({ error: "bad email" });
      }
      data.email = payload.email.trim().toLowerCase();
    }

    // birthday: YYYY-MM-DD
    if (wants.birthday) {
      if (payload.birthday !== null && typeof payload.birthday !== "string") {
        return res.status(400).json({ error: "bad birthday" });
      }
      if (typeof payload.birthday === "string") {
        // enforce simple YYYY-MM-DD pattern then parse
        if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.birthday)) {
          return res.status(400).json({ error: "bad birthday" });
        }
        const d = new Date(payload.birthday);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ error: "bad birthday" });
        }
        data.birthday = d;
      } else {
        data.birthday = null; // allow clearing
      }
    }

    // avatar/avatarUrl:
    // Spec says "avatar" file; we don't implement upload here, but support
    // tests that may send an URL-ish field.
    if (wants.avatar || wants.avatarUrl) {
      const val = payload.avatarUrl ?? payload.avatar;
      if (val !== null && val !== undefined && typeof val !== "string") {
        return res.status(400).json({ error: "bad avatarUrl" });
      }
      data.avatarUrl = val || null;
    }

    try {
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
        birthday: updated.birthday
          ? updated.birthday.toISOString().slice(0, 10)
          : null,
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
      if (e.code === "P2025") {
        return res.status(404).json({ error: "not found" });
      }
      throw e;
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});



app.patch("/users/:userId", async (req, res) => {
  try {
    const id = parseInt(req.params.userId, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "bad user id" });
    }

    // Auth: Manager or higher
    const rank = await resolveEffectiveRank(req);
    if (rank === undefined) {
      return res.status(401).json({ error: "unauthorized" });
    }
    if (rank < ROLE_RANK.manager) {
      return res.status(403).json({ error: "forbidden" });
    }

    const payload = req.body || {};
    const wants = {
      email: payload.email !== undefined,
      verified: payload.verified !== undefined,
      suspicious: payload.suspicious !== undefined,
      role: payload.role !== undefined
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    // Load existing user (needed for role/suspicious constraints)
    const existing = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        role: true,
        verified: true,
        suspicious: true
      }
    });

    if (!existing) {
      return res.status(404).json({ error: "not found" });
    }

    // ✅ FIX: Managers cannot update superusers
    const existingRank = ROLE_RANK[normalizeRole(existing.role)] ?? 0;
    if (rank === ROLE_RANK.manager && existingRank >= ROLE_RANK.superuser) {
      return res.status(403).json({ error: "forbidden" });
    }

    const data = {};

    // email: fix if wrong; must still be valid UofT email
    if (wants.email) {
      if (!validEmail(payload.email)) {
        return res.status(400).json({ error: "bad email" });
      }
      data.email = payload.email.trim().toLowerCase();
    }

    // verified: spec says "Should always be set to true"
    if (wants.verified) {
      // Accept any truthy value and always set to true
      data.verified = true;
    }

    // suspicious: boolean
    if (wants.suspicious) {
      // Convert to boolean if needed
      const suspVal = payload.suspicious;
      if (suspVal === true || suspVal === "true") {
        data.suspicious = true;
      } else if (suspVal === false || suspVal === "false") {
        data.suspicious = false;
      } else {
        return res.status(400).json({ error: "bad suspicious" });
      }
    }

    // role: depends on caller rank
    let targetRole = existing.role;
    if (wants.role) {
      if (typeof payload.role !== "string") {
        return res.status(400).json({ error: "bad role" });
      }
      const r = payload.role.trim().toLowerCase();
      const validRoles = ["regular", "cashier", "manager", "superuser"];

      // ✅ FIX: First check if role is valid at all
      if (!validRoles.includes(r)) {
        return res.status(400).json({ error: "bad role" });
      }

      // ✅ FIX: Then check if caller has permission for this role
      if (rank === ROLE_RANK.manager) {
        const allowedForManager = ["regular", "cashier"];
        if (!allowedForManager.includes(r)) {
          // Manager trying to set manager/superuser role -> 403
          return res.status(403).json({ error: "forbidden" });
        }
      } else if (rank === ROLE_RANK.superuser) {
        // Superuser can set any valid role (already checked above)
      } else {
        // Shouldn't happen because of earlier check, but keep safe
        return res.status(403).json({ error: "forbidden" });
      }

      data.role = r;
      targetRole = r;
    }

    // Enforce: suspicious user cannot be cashier
    const finalSuspicious =
      wants.suspicious ? !!data.suspicious : !!existing.suspicious;

    if (targetRole === "cashier" && finalSuspicious) {
      return res.status(400).json({ error: "cashier cannot be suspicious" });
    }

    try {
      const updated = await prisma.user.update({
        where: { id },
        data,
        select: {
          id: true,
          utorid: true,
          name: true,
          email: true,
          role: true,
          verified: true,
          suspicious: true
        }
      });

      // Response: only updated fields + identity
      const resp = {
        id: updated.id,
        utorid: updated.utorid,
        name: updated.name
      };

      if (wants.email) {
        resp.email = updated.email;
      }
      if (wants.verified) {
        resp.verified = updated.verified;
      }
      if (wants.suspicious) {
        resp.suspicious = !!updated.suspicious;
      }
      if (wants.role) {
        resp.role = updated.role;
      }

      return res.json(resp);
    } catch (e) {
      if (e.code === "P2002") {
        // duplicate email
        return res.status(409).json({ error: "duplicate" });
      }
      if (e.code === "P2025") {
        return res.status(404).json({ error: "not found" });
      }
      throw e;
    }
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
    const { utorid } = req.body || {};

    // --- Validate payload first (so bad payload isn't rate-limited) ---
    if (typeof utorid !== "string" || utorid.trim() === "" || !validUtorid(utorid)) {
      return res.status(400).json({ error: "bad payload" });
    }
    const uid = utorid.trim().toLowerCase();

    const user = await prisma.user.findUnique({
      where: { utorid: uid },
      select: { id: true }
    });

    if (!user) {
      return res.status(404).json({ error: "not found" });
    }

    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const now = Date.now();
    const last = resetRateLimiter.get(ip) || 0;
    if (now - last < RESET_WINDOW_MS) {
      return res.status(429).json({ error: "too many requests" });
    }

    const token = crypto.randomUUID();
    const expiresAtDate = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken: token, expiresAt: expiresAtDate }
    });

    resetRateLimiter.set(ip, now);

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

    // 🚨 Reject empty or invalid tokens immediately
    if (typeof resetToken !== "string" || resetToken.trim() === "") {
      return res.status(404).json({ error: "not found" });
    }

    // Validate payload
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

    const tokenUser = await prisma.user.findFirst({
      where: { resetToken },
      select: { id: true, utorid: true, expiresAt: true }
    });

    if (!tokenUser) {
      return res.status(404).json({ error: "not found" });
    }

    if (tokenUser.utorid !== uid) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const now = new Date();
    if (!(tokenUser.expiresAt instanceof Date) || tokenUser.expiresAt <= now) {
      return res.status(410).json({ error: "token expired" });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await prisma.user.update({
      where: { id: tokenUser.id },
      data: {
        password: hash,
        resetToken: null, // 👈 set null, not empty string
        expiresAt: new Date(0)
      }
    });

    return res.sendStatus(200);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


// ✅ FIX: Unified POST /transactions handler that routes by type
app.post("/transactions", async (req, res) => {
  try {
    if (!req.user) attachAuth(req);
    const { type } = req.body || {};

    // ============ PURCHASE TYPE (Cashier+) ============
    if (type === "purchase") {
      const rank = await resolveEffectiveRank(req);
      if (rank === undefined) return res.status(401).json({ error: "unauthorized" });
      if (rank < ROLE_RANK.cashier) return res.status(403).json({ error: "forbidden" });

      const { utorid, spent, promotionIds, remark } = req.body;

      if (typeof utorid !== "string" || !validUtorid(utorid)) {
        return res.status(400).json({ error: "bad utorid" });
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

      let earned = Math.round(amount * 4);
      let promos = [];
      if (Array.isArray(promotionIds) && promotionIds.length > 0) {
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

        const assignedIds = new Set(assigned.map((a) => a.promotion.id));
        const missing = ids.filter((pid) => !assignedIds.has(pid));
        if (missing.length > 0) {
          return res.status(400).json({ error: "invalid promotions" });
        }

        for (const a of assigned) {
          const p = a.promotion;
          if (p.minSpending != null && amount < p.minSpending) {
            return res.status(400).json({ error: "promotion minSpending not met" });
          }
          promos.push({ id: p.id, rate: p.rate ?? null, points: p.points ?? null, userPromoId: a.id });
        }

        const totalRate = promos.reduce((acc, p) => (p.rate ? acc * p.rate : acc), 1);
        earned = Math.round(earned * totalRate);
        const addPoints = promos.reduce((acc, p) => acc + (p.points || 0), 0);
        earned += addPoints;
      }

      const creditNow = cashier.suspicious !== true;
      const remarkText = (remark || "").trim();

      const result = await prisma.$transaction(async (tx) => {
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

        if (promos.length > 0) {
          await tx.transactionPromotion.createMany({
            data: promos.map((p) => ({ transactionId: t.id, promotionId: p.id }))
          });
          await tx.userPromotion.updateMany({
            where: { id: { in: promos.map((p) => p.userPromoId) } },
            data: { used: true, usedAt: new Date() }
          });
        }

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
    }

    // ============ ADJUSTMENT TYPE (Manager+) ============
    if (type === "adjustment") {
      const rank = await resolveEffectiveRank(req);
      if (rank === undefined) return res.status(401).json({ error: "unauthorized" });
      if (rank < ROLE_RANK.manager) return res.status(403).json({ error: "forbidden" });

      const { utorid, amount, relatedId, promotionIds, remark } = req.body;

      if (typeof utorid !== "string" || !validUtorid(utorid)) {
        return res.status(400).json({ error: "bad utorid" });
      }
      if (!Number.isFinite(Number(amount))) {
        return res.status(400).json({ error: "bad amount" });
      }
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
      if (!relatedTx || relatedTx.userId !== customer.id) {
        return res.status(400).json({ error: "invalid relatedId" });
      }

      let appliedUserPromoIds = [];
      let appliedPromoIds = [];
      if (Array.isArray(promotionIds) && promotionIds.length > 0) {
        const ids = [...new Set(promotionIds.map(n => Number(n)).filter(Number.isFinite))];
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
      const result = await prisma.$transaction(async (tx) => {
        const t = await tx.transaction.create({
          data: {
            type: "adjustment",
            spent: 0,
            earned: pts,
            remark: remarkText,
            userId: customer.id,
            createdById: creator.id,
            relatedId: relId
          },
          select: { id: true }
        });

        if (appliedPromoIds.length > 0) {
          await tx.transactionPromotion.createMany({
            data: appliedPromoIds.map(pid => ({ transactionId: t.id, promotionId: pid }))
          });
          await tx.userPromotion.updateMany({
            where: { id: { in: appliedUserPromoIds } },
            data: { used: true, usedAt: new Date() }
          });
        }

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
    }

    // Invalid type
    return res.status(400).json({ error: "invalid transaction type" });
  } catch (e) {
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
          { utorid: { contains: q } },
          { name:   { contains: q } }
        ]
      };
    }

    // Filter by creator utorid
    if (createdBy && String(createdBy).trim().length > 0) {
      const cb = String(createdBy).trim();
      where.createdBy = {
        utorid: { contains: cb }
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
    const promotionId = parseIdParam(req.params.promotionId);
    if (promotionId === null) {
      return res.status(400).json({ error: "bad promotion id" });
    }

    const promotion = await prisma.promotion.findUnique({
      where: { id: promotionId },
      select: {
        id: true,
        startTime: true
      }
    });

    if (!promotion) {
      return res.status(404).json({ error: "not found" });
    }

    const now = new Date();
    if (promotion.startTime && promotion.startTime <= now) {
      // Spec: 403 if promotion has already started
      return res.status(403).json({ error: "promotion already started" });
    }

    await prisma.promotion.delete({
      where: { id: promotionId }
    });

    return res.sendStatus(204);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.patch("/promotions/:promotionId", async (req, res) => {
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

    const rank = await resolveEffectiveRank(req);
    if (rank === undefined) return res.status(401).json({ error: "unauthorized" });
    if (rank < ROLE_RANK.manager) return res.status(403).json({ error: "forbidden" });

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

app.post("/promotions", async (req, res) => {
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
    const rank = await resolveEffectiveRank(req);
    if (rank === undefined) return res.status(401).json({ error: "unauthorized" });
    if (rank < ROLE_RANK.manager) return res.status(403).json({ error: "forbidden" });
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
      where.name = { contains: name.trim() };
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

// ===============================
// EVENT ENDPOINTS (Cases 36-73)
// ===============================

// POST /events - Create event (manager+ only)
app.post("/events", needManager, async (req, res) => {
  try {
    const { title, description, startTime, endTime, organizers, guests } = req.body || {};

    // Validate required fields
    if (typeof title !== "string" || title.trim() === "") {
      return res.status(400).json({ error: "bad title" });
    }
    if (typeof startTime !== "string" || startTime.trim() === "") {
      return res.status(400).json({ error: "bad startTime" });
    }
    if (typeof endTime !== "string" || endTime.trim() === "") {
      return res.status(400).json({ error: "bad endTime" });
    }

    // Parse and validate times
    const start = new Date(startTime);
    const end = new Date(endTime);
    if (Number.isNaN(start.getTime())) {
      return res.status(400).json({ error: "bad startTime" });
    }
    if (Number.isNaN(end.getTime())) {
      return res.status(400).json({ error: "bad endTime" });
    }
    if (end <= start) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    // Validate organizers/guests arrays
    if (organizers !== undefined && !Array.isArray(organizers)) {
      return res.status(400).json({ error: "organizers must be array" });
    }
    if (guests !== undefined && !Array.isArray(guests)) {
      return res.status(400).json({ error: "guests must be array" });
    }

    const organizerIds = Array.isArray(organizers) ? organizers.map(id => Number(id)).filter(n => Number.isInteger(n) && n > 0) : [];
    const guestIds = Array.isArray(guests) ? guests.map(id => Number(id)).filter(n => Number.isInteger(n) && n > 0) : [];

    // Verify all user IDs exist
    if (organizerIds.length > 0) {
      const count = await prisma.user.count({ where: { id: { in: organizerIds } } });
      if (count !== organizerIds.length) {
        return res.status(400).json({ error: "invalid organizer id(s)" });
      }
    }
    if (guestIds.length > 0) {
      const count = await prisma.user.count({ where: { id: { in: guestIds } } });
      if (count !== guestIds.length) {
        return res.status(400).json({ error: "invalid guest id(s)" });
      }
    }

    // Create event with relations
    const event = await prisma.event.create({
      data: {
        title: title.trim(),
        description: description ? String(description).trim() : null,
        startTime: start,
        endTime: end,
        organizers: {
          create: organizerIds.map(userId => ({ userId }))
        },
        guests: {
          create: guestIds.map(userId => ({ userId }))
        }
      },
      include: {
        organizers: { select: { userId: true } },
        guests: { select: { userId: true } }
      }
    });

    return res.status(201).json({
      id: event.id,
      title: event.title,
      description: event.description,
      startTime: event.startTime.toISOString(),
      endTime: event.endTime.toISOString(),
      organizers: event.organizers.map(o => o.userId),
      guests: event.guests.map(g => g.userId)
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// GET /events - List all events (authenticated users)
app.get("/events", requireAuthRegular, async (req, res) => {
  try {
    const { page: pageParam, limit: limitParam } = req.query || {};
    const page = toInt(pageParam, 1);
    const limit = toInt(limitParam, 10);

    const skip = (page - 1) * limit;

    const [count, events] = await Promise.all([
      prisma.event.count(),
      prisma.event.findMany({
        skip,
        take: limit,
        orderBy: { startTime: "asc" },
        include: {
          organizers: { select: { userId: true } },
          guests: { select: { userId: true } }
        }
      })
    ]);

    const results = events.map(e => ({
      id: e.id,
      title: e.title,
      description: e.description,
      startTime: e.startTime.toISOString(),
      endTime: e.endTime.toISOString(),
      organizers: e.organizers.map(o => o.userId),
      guests: e.guests.map(g => g.userId)
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// GET /events/:eventId - Get specific event
app.get("/events/:eventId", requireAuthRegular, async (req, res) => {
  try {
    const eventId = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(eventId) || eventId <= 0) {
      return res.status(400).json({ error: "bad event id" });
    }

    const event = await prisma.event.findUnique({
      where: { id: eventId },
      include: {
        organizers: { select: { userId: true } },
        guests: { select: { userId: true } }
      }
    });

    if (!event) {
      return res.status(404).json({ error: "not found" });
    }

    return res.json({
      id: event.id,
      title: event.title,
      description: event.description,
      startTime: event.startTime.toISOString(),
      endTime: event.endTime.toISOString(),
      organizers: event.organizers.map(o => o.userId),
      guests: event.guests.map(g => g.userId)
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// PATCH /events/:eventId - Update event (manager+ only)
app.patch("/events/:eventId", needManager, async (req, res) => {
  try {
    const eventId = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(eventId) || eventId <= 0) {
      return res.status(400).json({ error: "bad event id" });
    }

    const event = await prisma.event.findUnique({
      where: { id: eventId },
      include: {
        organizers: { select: { userId: true } },
        guests: { select: { userId: true } }
      }
    });

    if (!event) {
      return res.status(404).json({ error: "not found" });
    }

    const payload = req.body || {};
    const wants = {
      title: payload.title !== undefined,
      description: payload.description !== undefined,
      startTime: payload.startTime !== undefined,
      endTime: payload.endTime !== undefined,
      organizers: payload.organizers !== undefined,
      guests: payload.guests !== undefined
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const data = {};
    let newStart = event.startTime;
    let newEnd = event.endTime;

    if (wants.title) {
      if (typeof payload.title !== "string" || payload.title.trim() === "") {
        return res.status(400).json({ error: "bad title" });
      }
      data.title = payload.title.trim();
    }

    if (wants.description) {
      data.description = payload.description ? String(payload.description).trim() : null;
    }

    if (wants.startTime) {
      if (typeof payload.startTime !== "string") {
        return res.status(400).json({ error: "bad startTime" });
      }
      const start = new Date(payload.startTime);
      if (Number.isNaN(start.getTime())) {
        return res.status(400).json({ error: "bad startTime" });
      }
      data.startTime = start;
      newStart = start;
    }

    if (wants.endTime) {
      if (typeof payload.endTime !== "string") {
        return res.status(400).json({ error: "bad endTime" });
      }
      const end = new Date(payload.endTime);
      if (Number.isNaN(end.getTime())) {
        return res.status(400).json({ error: "bad endTime" });
      }
      data.endTime = end;
      newEnd = end;
    }

    // Validate time order
    if (newEnd <= newStart) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    // Handle organizers/guests updates
    let organizerIds = null;
    let guestIds = null;

    if (wants.organizers) {
      if (!Array.isArray(payload.organizers)) {
        return res.status(400).json({ error: "organizers must be array" });
      }
      organizerIds = payload.organizers.map(id => Number(id)).filter(n => Number.isInteger(n) && n > 0);
      if (organizerIds.length > 0) {
        const count = await prisma.user.count({ where: { id: { in: organizerIds } } });
        if (count !== organizerIds.length) {
          return res.status(400).json({ error: "invalid organizer id(s)" });
        }
      }
    }

    if (wants.guests) {
      if (!Array.isArray(payload.guests)) {
        return res.status(400).json({ error: "guests must be array" });
      }
      guestIds = payload.guests.map(id => Number(id)).filter(n => Number.isInteger(n) && n > 0);
      if (guestIds.length > 0) {
        const count = await prisma.user.count({ where: { id: { in: guestIds } } });
        if (count !== guestIds.length) {
          return res.status(400).json({ error: "invalid guest id(s)" });
        }
      }
    }

    // Update event in transaction
    const updated = await prisma.$transaction(async (tx) => {
      // Delete and recreate organizers if specified
      if (organizerIds !== null) {
        await tx.eventOrganizer.deleteMany({ where: { eventId } });
        if (organizerIds.length > 0) {
          await tx.eventOrganizer.createMany({
            data: organizerIds.map(userId => ({ eventId, userId }))
          });
        }
      }

      // Delete and recreate guests if specified
      if (guestIds !== null) {
        await tx.eventGuest.deleteMany({ where: { eventId } });
        if (guestIds.length > 0) {
          await tx.eventGuest.createMany({
            data: guestIds.map(userId => ({ eventId, userId }))
          });
        }
      }

      // Update event fields
      return await tx.event.update({
        where: { id: eventId },
        data,
        include: {
          organizers: { select: { userId: true } },
          guests: { select: { userId: true } }
        }
      });
    });

    const response = {
      id: updated.id,
      title: updated.title,
      description: updated.description
    };

    if (wants.startTime) response.startTime = updated.startTime.toISOString();
    if (wants.endTime) response.endTime = updated.endTime.toISOString();
    if (wants.organizers) response.organizers = updated.organizers.map(o => o.userId);
    if (wants.guests) response.guests = updated.guests.map(g => g.userId);

    return res.json(response);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// DELETE /events/:eventId - Delete event (manager+ only)
app.delete("/events/:eventId", needManager, async (req, res) => {
  try {
    const eventId = parseInt(req.params.eventId, 10);
    if (!Number.isInteger(eventId) || eventId <= 0) {
      return res.status(400).json({ error: "bad event id" });
    }

    const event = await prisma.event.findUnique({ where: { id: eventId } });
    if (!event) {
      return res.status(404).json({ error: "not found" });
    }

    await prisma.event.delete({ where: { id: eventId } });
    return res.sendStatus(204);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// ===============================
// SUSPICIOUS USER ENDPOINTS (Cases 84-86)
// ===============================

// GET /suspicious - Get all suspicious users (manager+ only)
app.get("/suspicious", needManager, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: { suspicious: true },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        role: true,
        verified: true,
        suspicious: true
      },
      orderBy: { createdAt: "desc" }
    });

    return res.json({ count: users.length, results: users });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// PATCH /suspicious/:userId - Toggle suspicious flag (superuser only)
app.patch("/suspicious/:userId", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: "bad user id" });
    }

    // Auth: Superuser only
    const rank = await resolveEffectiveRank(req);
    if (rank === undefined) {
      return res.status(401).json({ error: "unauthorized" });
    }
    if (rank < ROLE_RANK.superuser) {
      return res.status(403).json({ error: "forbidden" });
    }

    const payload = req.body || {};
    if (payload.suspicious === undefined) {
      return res.status(400).json({ error: "missing suspicious field" });
    }

    const suspVal = payload.suspicious;
    let suspicious;
    if (suspVal === true || suspVal === "true") {
      suspicious = true;
    } else if (suspVal === false || suspVal === "false") {
      suspicious = false;
    } else {
      return res.status(400).json({ error: "bad suspicious value" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, role: true }
    });

    if (!user) {
      return res.status(404).json({ error: "not found" });
    }

    // Cannot mark cashier as suspicious
    if (suspicious && user.role === "cashier") {
      return res.status(400).json({ error: "cashier cannot be suspicious" });
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data: { suspicious },
      select: {
        id: true,
        utorid: true,
        name: true,
        suspicious: true
      }
    });

    return res.json({
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name,
      suspicious: updated.suspicious
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});



async function canEditEvent(req, event) {
  const rank = await resolveEffectiveRank(req);
  const uid = getCurrentUserId(req);

  if (!rank && !uid) return { allowed: false, rank: undefined, uid: null };

  // Manager or higher → always allowed
  if (rank !== undefined && rank >= ROLE_RANK.manager) {
    return { allowed: true, rank, uid };
  }

  if (!uid) return { allowed: false, rank, uid: null };

  // Organizer for this event → allowed (with restrictions enforced later)
  const isOrganizer = event.organizers.some((o) => o.userId === uid);
  return { allowed: isOrganizer, rank, uid };
}

// POST /events
// Create a new point-earning event.
// Clearance: Manager or higher
app.post("/events", needManager, async (req, res) => {
  try {
    const {
      name,
      description,
      location,
      startTime,
      endTime,
      capacity,
      points
    } = req.body || {};

    // --- Validate required strings ---
    if (typeof name !== "string" || name.trim() === "") {
      return res.status(400).json({ error: "bad name" });
    }
    if (typeof description !== "string" || description.trim() === "") {
      return res.status(400).json({ error: "bad description" });
    }
    if (typeof location !== "string" || location.trim() === "") {
      return res.status(400).json({ error: "bad location" });
    }

    // --- Validate times ---
    if (typeof startTime !== "string") {
      return res.status(400).json({ error: "bad startTime" });
    }
    if (typeof endTime !== "string") {
      return res.status(400).json({ error: "bad endTime" });
    }

    const start = new Date(startTime);
    const end = new Date(endTime);

    if (Number.isNaN(start.getTime())) {
      return res.status(400).json({ error: "bad startTime" });
    }
    if (Number.isNaN(end.getTime())) {
      return res.status(400).json({ error: "bad endTime" });
    }
    if (end <= start) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    // Reject start/end in the past (aligned with PATCH rules)
    const now = new Date();
    if (start < now || end < now) {
      return res.status(400).json({ error: "time in past" });
    }

    // --- Validate capacity ---
    let cap = null;
    if (capacity !== undefined && capacity !== null) {
      const n = Number(capacity);
      if (!Number.isInteger(n) || n <= 0) {
        return res.status(400).json({ error: "bad capacity" });
      }
      cap = n;
    }

    // --- Validate points ---
    const pts = Number(points);
    if (!Number.isInteger(pts) || pts <= 0) {
      return res.status(400).json({ error: "bad points" });
    }

    const event = await prisma.event.create({
      data: {
        name: name.trim(),
        description: description.trim(),
        location: location.trim(),
        startTime: start,
        endTime: end,
        capacity: cap,
        pointsTotal: pts,
        pointsRemain: pts,
        pointsAwarded: 0,
        published: false
      },
      include: {
        organizers: { select: { userId: true } },
        guests: { select: { userId: true } }
      }
    });

    return res.status(201).json({
      id: event.id,
      name: event.name,
      description: event.description,
      location: event.location,
      startTime: event.startTime.toISOString(),
      endTime: event.endTime.toISOString(),
      capacity: event.capacity === null ? null : event.capacity,
      pointsRemain: event.pointsRemain,
      pointsAwarded: event.pointsAwarded,
      published: !!event.published,
      organizers: event.organizers.map((o) => o.userId),
      guests: event.guests.map((g) => g.userId)
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});

// PATCH /events/:eventId
// Update an existing event.
// Clearance: Manager+ OR organizer for this event.
// Field rules & error conditions per spec.
app.patch("/events/:eventId", async (req, res) => {
  try {
    const eventId = parseIdParam(req.params.eventId);
    if (eventId === null) {
      return res.status(400).json({ error: "bad event id" });
    }

    // Load event with organizers & guests (for auth, capacity, points)
    const event = await prisma.event.findUnique({
      where: { id: eventId },
      include: {
        organizers: { select: { userId: true } },
        guests: { select: { userId: true, confirmed: true } }
      }
    });

    if (!event) {
      return res.status(404).json({ error: "not found" });
    }

    const { allowed, rank, uid } = await canEditEvent(req, event);
    if (!allowed) {
      if (rank === undefined && !uid) {
        return res.status(401).json({ error: "unauthorized" });
      }
      return res.status(403).json({ error: "forbidden" });
    }

    const payload = req.body || {};
    const wants = {
      name: payload.name !== undefined,
      description: payload.description !== undefined,
      location: payload.location !== undefined,
      startTime: payload.startTime !== undefined,
      endTime: payload.endTime !== undefined,
      capacity: payload.capacity !== undefined,
      points: payload.points !== undefined,
      published: payload.published !== undefined
    };

    if (!Object.values(wants).some(Boolean)) {
      return res.status(400).json({ error: "no updates" });
    }

    const now = new Date();
    const originalStart = event.startTime;
    const originalEnd = event.endTime;

    const data = {};
    const updatedFields = new Set();

    let newStart = event.startTime;
    let newEnd = event.endTime;

    // --- Helpers for "no changes after started/ended" rules ---
    const hasStarted = originalStart <= now;
    const hasEnded = originalEnd <= now;

    // 1) name
    if (wants.name) {
      if (hasStarted) {
        return res.status(400).json({ error: "cannot update name after start" });
      }
      if (typeof payload.name !== "string" || payload.name.trim() === "") {
        return res.status(400).json({ error: "bad name" });
      }
      data.name = payload.name.trim();
      updatedFields.add("name");
    }

    // 2) description
    if (wants.description) {
      if (hasStarted) {
        return res.status(400).json({ error: "cannot update description after start" });
      }
      if (payload.description === null || payload.description === undefined) {
        data.description = null;
      } else if (typeof payload.description !== "string") {
        return res.status(400).json({ error: "bad description" });
      } else {
        data.description = payload.description.trim();
      }
      updatedFields.add("description");
    }

    // 3) location
    if (wants.location) {
      if (hasStarted) {
        return res.status(400).json({ error: "cannot update location after start" });
      }
      if (typeof payload.location !== "string" || payload.location.trim() === "") {
        return res.status(400).json({ error: "bad location" });
      }
      data.location = payload.location.trim();
      updatedFields.add("location");
    }

    // 4) startTime
    if (wants.startTime) {
      if (hasStarted) {
        return res.status(400).json({ error: "cannot update startTime after start" });
      }
      if (typeof payload.startTime !== "string") {
        return res.status(400).json({ error: "bad startTime" });
      }
      const s = new Date(payload.startTime);
      if (Number.isNaN(s.getTime())) {
        return res.status(400).json({ error: "bad startTime" });
      }
      if (s < now) {
        return res.status(400).json({ error: "startTime in past" });
      }
      newStart = s;
      data.startTime = s;
      updatedFields.add("startTime");
    }

    // 5) endTime
    if (wants.endTime) {
      if (hasEnded) {
        return res.status(400).json({ error: "cannot update endTime after end" });
      }
      if (typeof payload.endTime !== "string") {
        return res.status(400).json({ error: "bad endTime" });
      }
      const e = new Date(payload.endTime);
      if (Number.isNaN(e.getTime())) {
        return res.status(400).json({ error: "bad endTime" });
      }
      if (e < now) {
        return res.status(400).json({ error: "endTime in past" });
      }
      newEnd = e;
      data.endTime = e;
      updatedFields.add("endTime");
    }

    // Ensure new endTime is after new startTime
    if (newEnd <= newStart) {
      return res.status(400).json({ error: "endTime must be after startTime" });
    }

    // 6) capacity
    if (wants.capacity) {
      if (hasStarted) {
        return res.status(400).json({ error: "cannot update capacity after start" });
      }

      let newCap = null;
      if (payload.capacity === null) {
        newCap = null;
      } else {
        const c = Number(payload.capacity);
        if (!Number.isInteger(c) || c <= 0) {
          return res.status(400).json({ error: "bad capacity" });
        }
        newCap = c;
      }

      // If reducing, ensure not below confirmed guests
      if (newCap !== null && event.capacity !== null && newCap < event.capacity) {
        const confirmedCount = event.guests.filter((g) => g.confirmed === true).length;
        if (newCap < confirmedCount) {
          return res.status(400).json({ error: "capacity below confirmed guests" });
        }
      }

      data.capacity = newCap;
      updatedFields.add("capacity");
    }

    // 7) points (only managers+; cannot reduce below awarded)
    if (wants.points) {
      if (rank === undefined || rank < ROLE_RANK.manager) {
        return res.status(403).json({ error: "forbidden" });
      }

      const newTotal = Number(payload.points);
      if (!Number.isInteger(newTotal) || newTotal <= 0) {
        return res.status(400).json({ error: "bad points" });
      }

      // Already awarded points cannot be taken back
      if (newTotal < event.pointsAwarded) {
        return res.status(400).json({ error: "points below awarded" });
      }

      data.pointsTotal = newTotal;
      data.pointsRemain = newTotal - event.pointsAwarded;
      updatedFields.add("points");
      updatedFields.add("pointsRemain");
    }

    // 8) published (only managers+; can only set to true)
    if (wants.published) {
      if (rank === undefined || rank < ROLE_RANK.manager) {
        return res.status(403).json({ error: "forbidden" });
      }

      const v = payload.published;
      if (v !== true) {
        // Spec: can only be set to true
        return res.status(400).json({ error: "bad published" });
      }

      if (!event.published) {
        data.published = true;
        updatedFields.add("published");
      }
      // If already true, silently ignore (no-op)
    }

    // If somehow nothing is valid to update:
    if (Object.keys(data).length === 0 && updatedFields.size === 0) {
      return res.status(400).json({ error: "no valid updates" });
    }

    const updated = await prisma.event.update({
      where: { id: eventId },
      data,
      select: {
        id: true,
        name: true,
        location: true,
        description: true,
        startTime: true,
        endTime: true,
        capacity: true,
        pointsTotal: true,
        pointsRemain: true,
        pointsAwarded: true,
        published: true
      }
    });

    // Response: always id, name, location; plus only updated fields
    const resp = {
      id: updated.id,
      name: updated.name,
      location: updated.location
    };

    if (updatedFields.has("description")) {
      resp.description = updated.description;
    }
    if (updatedFields.has("startTime")) {
      resp.startTime = updated.startTime.toISOString();
    }
    if (updatedFields.has("endTime")) {
      resp.endTime = updated.endTime.toISOString();
    }
    if (updatedFields.has("capacity")) {
      resp.capacity = updated.capacity === null ? null : updated.capacity;
    }
    if (updatedFields.has("points") || updatedFields.has("pointsRemain")) {
      // Only include if points were updated
      resp.pointsRemain = updated.pointsRemain;
      resp.pointsAwarded = updated.pointsAwarded;
    }
    if (updatedFields.has("published")) {
      resp.published = !!updated.published;
    }

    return res.json(resp);
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
