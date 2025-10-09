const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const basicAuth = async (req, res, next) => { 
    const authHeader = req.headers['authorization']; 
    if (!authHeader) { 
        req.user = null;
        return next();
    }

    // TODO:
    // 1. Parse authHeader to extract the username and password.
    // 2. Check the database for the user with matching username and password.
    // 3. If found, set req.user to it and allow the next middleware to run.
    // 4. If not, immediate respond with status code 401 and this JSON data: { message: "Invalid credentials" } 
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || !/^Basic$/i.test(parts[0])) { 
        return res.status(401).json({ message: 'Invalid credentials' });
     } 
    let decoded; 
    decoded = Buffer.from(parts[1], 'base64').toString('utf8');
    const sep = decoded.indexOf(':'); 
    if (sep < 0) { 
        return res.status(401).json({ message: 'Invalid credentials' }); 
    } 
    const username = decoded.slice(0, sep); 
    const password = decoded.slice(sep + 1); 
    if (!username || !password) { 
        return res.status(401).json({ message: 'Invalid credentials' }); 
    }
    const user = await prisma.user.findUnique({ where: { username } }); 
    if (!user || user.password !== password) { 
        return res.status(401).json({ message: 'Invalid credentials' }); 
    } 
    req.user = user;  
    return next();  
}; 

module.exports = basicAuth;