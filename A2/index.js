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
})
 
const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});