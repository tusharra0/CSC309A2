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

app.get("/", (req, res) => {
    res.send("Hello World!");
});

// ADD YOUR WORK HERE
const data = [
  {
    title: "Buy groceries",
    description: "Milk, Bread, Eggs, Butter",
    completed: false
  },
  {
    title: "Walk the dog",
    description: "Take Bella for a walk in the park",
    completed: true
  },
  {
    title: "Read a book",
    description: "Finish reading 'The Great Gatsby'",
    completed: false
  }
];


app.param("noteId", (req, res, next, noteId) => {
  const id = Number(noteId);
  if (!Number.isInteger(id) || id < 0) {
    return res.status(400).send("Bad request");
  }
  if (id >= data.length) {
    return res.status(404).send("Not found");
  }
  req.noteId = id;
  req.note = data[id];
  next();
});


app.get("/notes", (req, res) => {
    const { done } = req.query;
    let filteredNotes = data;

  if (done === "true") {
    filteredNotes = data.filter(n => n.completed === true);
  } else if (done === "false") {
    filteredNotes = data.filter(n => n.completed === false);
  }else if (done !== undefined) {
  
    return res.status(400).send("Bad request");
  }
  res.json(filteredNotes);
});

app.get("/notes/:noteId", (req, res) => {
    res.json(req.note);
});

app.post("/notes", (req, res) => {
  const { title, description, completed } = req.body;

    let completedBool = false;
    if (completed !== undefined) {
        if (typeof completed === "boolean") {
        completedBool = completed;
        } else if (typeof completed === "string") {
            if (completed === "true") completedBool = true;
            else if (completed === "false") completedBool = false;
            else return res.status(400).send("Bad request");
        } else {
        return res.status(400).send("Bad request");
        }
    }

  const id = data.length;

  const stored = {
    title,
    description,
    completed: completedBool
  };
  data.push(stored);

  return res.status(201).json({
    id,
    ...stored
  });
});

app.patch("/notes/:noteId", (req, res) => {
  const { done } = req.query;

  if (done !== "true" && done !== "false") {
    return res.status(400).send("Bad request");
  }

  req.note.completed = (done === "true");
  return res.status(200).json(req.note); 

});

// ==================

const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});

const basicAuth = require('./middleware/basicAuth');

app.get('/hello', basicAuth, (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

app.post('/users', async (req, res) => {
    const { username, password } = req.body || {};
    if(
        typeof username !== 'string' || typeof password !== 'string' || username.trim() === '' || password.trim() === ''
    ) {
        return res.status(400).json({message: 'Invalid payload' });
    }
    
        const existing = await prisma.user.findUnique({ where: { username }});
        if (existing) {
            return res.status(409).json({message: 'A user with that username already exists' });
        }
        const user = await prisma.user.create({
            data: { username, password }
        });
        return res.status(201).json(user);
});

app.post('/notes', basicAuth, async (req, res) => {
    if (!req.user) { return res.status(401).json({ message: 'Not authenticated' }); 
    }
    const { title, description, completed, public: isPublic } = req.body || {};
    const invalid = 
    typeof title !== 'string' || title.trim() === '' || typeof description !== 'string' || description.trim() === '' || typeof completed !== 'boolean' || typeof isPublic !== 'boolean'; 
    if (invalid) {
         return res.status(400).json({ message: 'Invalid payload' }); 
        }
        const note = await prisma.note.create({ 
            data: { 
                title: title.trim(), 
                description: description.trim(), 
                completed,
                 public: isPublic,
                  userId: req.user.id, }, 
                });  
        return res.status(201).json(note);
});

app.get('/notes', async (req, res) => { 
    const { done } = req.query;
    let where = { public: true }; 
    if (done !== undefined) { 
        if (done !== 'true' && done !== 'false') { 
            return res.status(400).json({ message: 'Invalid payload' });
         } 
         where.completed = (done === 'true'); 
        }
        const notes = await prisma.note.findMany({ where }); 
        return res.json(notes);
});

app.get('/notes/:noteId', basicAuth, async (req, res) => { 
    if (!req.user) { 
        return res.status(401).json({ message: 'Not authenticated' }); 
    } 
    const { noteId } = req.params;
    const id = Number(noteId); 
    if (!Number.isInteger(id) || id <= 0) { 
        return res.status(404).json({ message: 'Not found' }); 
    } 
    const note = await prisma.note.findUnique({ where: { id } });
    if (!note) { 
        return res.status(404).json({ message: 'Not found' }); 
    }
    if (note.userId !== req.user.id) { 
        return res.status(403).json({ message: 'Not permitted' }); 
    }
    return res.json(note); 
});


app.patch('/notes/:noteId', basicAuth, async (req, res) => {
  
    if (!req.user) {
        return res.status(401).json({ message: 'Not authenticated' });
    }

    const { noteId } = req.params;
    const id = Number(noteId);
    if (!Number.isInteger(id) || id <= 0) {
        return res.status(404).json({ message: 'Not found' });
    }

    const note = await prisma.note.findUnique({ where: { id } });
    if (!note) {
        return res.status(404).json({ message: 'Not found' });
    }
    if (note.userId !== req.user.id) {
        return res.status(403).json({ message: 'Not permitted' });
    }
    const { title, description, completed, public: isPublic } = req.body || {};
    const providedKeys = Object.keys(req.body || {});
    const allowedKeys = ['title', 'description', 'completed', 'public'];

    if (
        providedKeys.length === 0 ||
        providedKeys.some(k => !allowedKeys.includes(k))
    ) {
        return res.status(400).json({ message: 'Invalid payload' });
    }

    if (providedKeys.includes('title') &&
        (typeof title !== 'string' || title.trim() === '')
    ) {
        return res.status(400).json({ message: 'Invalid payload' });
    }
    if (providedKeys.includes('description') &&
        (typeof description !== 'string' || description.trim() === '')
    ) {
        return res.status(400).json({ message: 'Invalid payload' });
    }
    if (providedKeys.includes('completed') && typeof completed !== 'boolean') {
        return res.status(400).json({ message: 'Invalid payload' });
    }
    if (providedKeys.includes('public') && typeof isPublic !== 'boolean') {
        return res.status(400).json({ message: 'Invalid payload' });
    }

 
    const data = {};
    if (providedKeys.includes('title')) data.title = title.trim();
    if (providedKeys.includes('description')) data.description = description.trim();
    if (providedKeys.includes('completed')) data.completed = completed;
    if (providedKeys.includes('public')) data.public = isPublic;


    const updated = await prisma.note.update({
    where: { id },
    data
    });
    return res.json(updated);
    
    });