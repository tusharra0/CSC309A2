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
    id: 0,
    title: "Buy groceries",
    description: "Milk, Bread, Eggs, Butter",
    completed: false
  },
  {
    id: 1,
    title: "Walk the dog",
    description: "Take Bella for a walk in the park",
    completed: true
  },
  {
    id: 2,
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
    filteredNotes = data.filter(note => note.completed === true);
  } else if (done === "false") {
    filteredNotes = data.filter(note => note.completed === false);
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

  const newNote = {
    id: data.length,
    title,
    description,
    completed: completed === undefined ? false : Boolean(completed)
  };

  data.push(newNote); 
  res.status(201).json(newNote); 
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