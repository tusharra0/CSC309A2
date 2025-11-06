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

const path = require("path");
const fs = require("fs");
const multer = require("multer");
const sharp = require("sharp");
app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")));


const upload = multer({
  storage: multer.memoryStorage(), // we’ll convert to PNG with sharp
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp"].includes(file.mimetype);
    if (!ok) return cb(new Error("invalid image type"), false);
    cb(null, true);
  }
});


function getRole(req){ return (req.headers["x-role"] || "").toLowerCase(); }

function checkRole(req, res, next) {
  const role = getRole(req);
  if (!role) return res.status(401).json({ error: "unauthorized" });
  if (role === "cashier" || role === "manager" || role === "superuser") return next();
  return res.status(403).json({ error: "forbidden" });
}

function requireAuth(req, res, next) {
  const role = getRole(req);
  if (!role) return res.status(401).json({ error: "unauthorized" }); 
  next();
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
  const r = getRole(req);
  if (!r) return res.status(401).json({ error: "unauthorized" });
  if (r==="manager" || r==="superuser") return next();
  return res.status(403).json({ error: "forbidden" });
}

function parseBirthday(s){
  if (typeof s !== "string") return undefined;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null; // invalid format
  const d = new Date(s + "T00:00:00.000Z");
  const [Y,M,D] = s.split("-").map(n=>parseInt(n,10));
  if (d.getUTCFullYear()!==Y || d.getUTCMonth()+1!==M || d.getUTCDate()!==D) return null;
  return d;
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

app.get("/users/:userId", requireAuth, async (req,res)=>{
  try{
    const id = parseInt(req.params.userId,10);
    if(!Number.isInteger(id) || id<=0) return res.status(400).json({error:"bad user id"});

    const caller = getRole(req);
    const isManager = caller==="manager" || caller==="superuser";

    const selectBase = {
      id:true, utorid:true, name:true, points:true, verified:true,
      promotions:{
        where:{ used:false, promotion:{ is:{ type:"onetime" } } },
        select:{ promotion:{ select:{ id:true, name:true, minSpending:true, rate:true, points:true } } }
      }
    };

    const selectManagerOnly = {
      email:true, birthday:true, role:true, createdAt:true, lastLogin:true, avatarUrl:true, suspicious:true
    };

    const user = await prisma.user.findUnique({
      where:{ id },
      select: isManager ? { ...selectBase, ...selectManagerOnly } : selectBase
    });

    if(!user) return res.status(404).json({error:"not found"});

    const promos = user.promotions.map(x=>({...x.promotion}));

    const baseOut = {
      id:user.id, utorid:user.utorid, name:user.name,
      points:user.points, verified:user.verified, promotions:promos
    };

    if(!isManager) return res.json(baseOut);

    return res.json({
      ...baseOut,
      email:user.email,
      birthday:user.birthday ? user.birthday.toISOString().slice(0,10) : null,
      role:user.role,
      createdAt: user.createdAt?.toISOString() ?? null,
      lastLogin: user.lastLogin?.toISOString() ?? null,
      avatarUrl:user.avatarUrl,
      suspicious:user.suspicious
    });
  }catch(e){
    console.error(e);
    res.status(500).json({error:"server broke"});
  }
});






app.patch("/users/:userId", needManager, async (req, res) => {
  try {
    const id = parseInt(req.params.userId, 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "bad user id" });

    const callerRole = getRole(req);

    const { email, verified, suspicious, role } = req.body || {};
    if ([email, verified, suspicious, role].every(v => v === undefined))
      return res.status(400).json({ error: "no updatable fields" });

    const current = await prisma.user.findUnique({
      where: { id },
      select: { id:true, utorid:true, name:true, role:true, suspicious:true, email:true }
    });
    if (!current) return res.status(404).json({ error: "not found" });

    const updates = {};

    if (email !== undefined) {
      const em = String(email).trim().toLowerCase();
      if (!validEmail(em)) return res.status(400).json({ error: "bad email" });
      if (em !== current.email) updates.email = em;
    }

    if (verified !== undefined) {
      const v = toBool(verified);
      if (v !== true) return res.status(400).json({ error: "verified must be true" });
      updates.verified = true;
    }

    if (role !== undefined) {
      const r = String(role).trim().toLowerCase();
      const mgrAllowed = new Set(["regular","cashier"]);
      const superAllowed = new Set(["regular","cashier","manager","superuser"]);
      if (callerRole === "manager" && !mgrAllowed.has(r)) return res.status(403).json({ error: "forbidden role change" });
      if (callerRole === "superuser" && !superAllowed.has(r)) return res.status(400).json({ error: "bad role" });
      if (callerRole !== "manager" && callerRole !== "superuser") return res.status(403).json({ error: "need manager or higher" });
      if (r !== current.role) updates.role = r;
      
      if (r === "cashier") updates.suspicious = false;
    }

    if (suspicious !== undefined) {
      const s = toBool(suspicious);
      if (s === undefined) return res.status(400).json({ error: "bad suspicious" });
  
      const futureRole = updates.role ?? current.role;
      if (futureRole === "cashier" && s === true) return res.status(400).json({ error: "cashier cannot be suspicious" });
      updates.suspicious = s;
    }

    if (Object.keys(updates).length === 0)
      return res.json({ id: current.id, utorid: current.utorid, name: current.name });

    const updated = await prisma.user.update({
      where: { id },
      data: updates,
      select: { id:true, utorid:true, name:true, email:true, verified:true, suspicious:true, role:true }
    });

    const resp = { id: updated.id, utorid: updated.utorid, name: updated.name };
    for (const k of Object.keys(updates)) resp[k] = updated[k];
    return res.json(resp);
  } catch (e) {
    if (e?.code === "P2002") return res.status(409).json({ error: "duplicate" });
    console.error(e);
    return res.status(500).json({ error: "internal" });
  }
});


app.patch("/users/me", requireAuth, upload.single("avatar"), async (req, res) => {
  try {
    const uid = parseInt(req.headers["x-user-id"], 10);
    if (!Number.isInteger(uid) || uid <= 0) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const current = await prisma.user.findUnique({ where: { id: uid } });
    if (!current) return res.status(404).json({ error: "not found" });


    const { name, email, birthday } = req.body || {};

    const updates = {};


    if (name !== undefined) {
      if (!validName(name)) return res.status(400).json({ error: "bad name" });
      if (name.trim() !== current.name) updates.name = name.trim();
    }


    if (email !== undefined) {
      const em = String(email).trim().toLowerCase();
      if (!validEmail(em)) return res.status(400).json({ error: "bad email" });
      if (em !== current.email) updates.email = em;
    }

  
    if (birthday !== undefined) {
      if (birthday === "" || birthday === null) {
        updates.birthday = null; 
      } else {
        const b = parseBirthday(String(birthday));
        if (b === null) return res.status(400).json({ error: "bad birthday" });
        if (b !== undefined) updates.birthday = b;
      }
    }

    
    let avatarUrl = current.avatarUrl || null;
    if (req.file) {
    
      const dir = path.join(__dirname, "public", "uploads", "avatars");
      fs.mkdirSync(dir, { recursive: true });
      const filename = `${current.utorid}.png`; 
      const filepath = path.join(dir, filename);

      await sharp(req.file.buffer)
        .png()
        .toFile(filepath);

      avatarUrl = `/uploads/avatars/${filename}`;
      updates.avatarUrl = avatarUrl;
    }

    if (Object.keys(updates).length === 0) {
      return res.json({
        id: current.id,
        utorid: current.utorid,
        name: current.name,
        email: current.email,
        birthday: current.birthday ? current.birthday.toISOString().slice(0,10) : null,
        role: current.role,           // string/enum as in your schema
        points: current.points,
        createdAt: current.createdAt?.toISOString() ?? null,
        lastLogin: current.lastLogin?.toISOString() ?? null,
        verified: current.verified,
        avatarUrl: avatarUrl
      });
    }

    let updated;
    try {
      updated = await prisma.user.update({
        where: { id: uid },
        data: updates
      });
    } catch (e) {
      if (e?.code === "P2002") {
        return res.status(409).json({ error: "duplicate" }); 
      }
      throw e;
    }

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
  } catch (err) {
    if (err?.message === "invalid image type") {
      return res.status(400).json({ error: "invalid image type" });
    }
    console.error(err);
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