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


app.get("/users/:userId", needManager, async (req, res) => {
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
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true,
        promotions: {
          where: {
            used: false,
            promotion: { is: { type: "onetime" } }
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

    const promotions = user.promotions.map(x => ({
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
      email: user.email,
      birthday: user.birthday ? user.birthday.toISOString().slice(0, 10) : null,
      role: user.role,
      points: user.points,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      verified: user.verified,
      avatarUrl: user.avatarUrl,
      promotions
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server broke" });
  }
});


app.patch("/users/:userId", needManager, async (req, res) => {
  try {
    const id = parseInt(req.params.userId, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "bad user id" });
    }

    const callerRole = String(req.headers["x-role"] || "").toLowerCase();

    const { email, verified, suspicious, role } = req.body || {};

    if (
      email === undefined &&
      verified === undefined &&
      suspicious === undefined &&
      role === undefined
    ) {
      return res.status(400).json({ error: "no updatable fields" });
    }

    const current = await prisma.user.findUnique({
      where: { id },
      select: { id: true, utorid: true, name: true, role: true, suspicious: true, email: true }
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


    let targetRole = current.role;
    if (role !== undefined) {
      const r = String(role).trim().toLowerCase();
      const allowedForManager = new Set(["regular", "cashier"]);
      const allowedForSuper = new Set(["regular", "cashier", "manager", "superuser"]);

      if (callerRole === "manager" && !allowedForManager.has(r)) {
        return res.status(403).json({ error: "forbidden role change" });
      }
      if (callerRole === "superuser" && !allowedForSuper.has(r)) {
        return res.status(400).json({ error: "bad role" });
      }
      if (callerRole !== "manager" && callerRole !== "superuser") {
        return res.status(403).json({ error: "need manager or higher" });
      }

      targetRole = r;
      if (targetRole !== current.role) updates.role = targetRole;
    }

   
    let targetSuspicious = current.suspicious;

    if (suspicious !== undefined) {
      const s = toBool(suspicious);
      if (s === undefined) return res.status(400).json({ error: "bad suspicious" });
      targetSuspicious = s;
    }

    const finalRole = targetRole;
    if (finalRole === "cashier") {
      if (suspicious !== undefined && targetSuspicious === true) {
        return res.status(400).json({ error: "cashier cannot be suspicious" });
      }
 
      if (current.role !== "cashier" || current.suspicious !== false) {
        targetSuspicious = false;
      }
    } else {
      
    }

    if (targetSuspicious !== current.suspicious) {
      updates.suspicious = targetSuspicious;
    }

    
    if (Object.keys(updates).length === 0) {
      return res.json({
        id: current.id,
        utorid: current.utorid,
        name: current.name
      });
    }

    const updated = await prisma.user.update({
      where: { id },
      data: updates,
      select: { id: true, utorid: true, name: true, email: true, verified: true, suspicious: true, role: true }
    });

    
    const resp = {
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name
    };
    for (const k of Object.keys(updates)) {
      resp[k] = updated[k];
    }

    return res.json(resp);
  } catch (e) {
    if (e?.code === "P2002") {
      return res.status(409).json({ error: "duplicate" }); // e.g., unique email conflict
    }
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