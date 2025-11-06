import "./App.css";
import { useState } from "react";
import NewTodo from "./components/NewTodo";
import TodoItem from "./components/TodoItem";

// You can use this to seed your TODO list
const seed = [
    { id: 0, text: "Submit assignment 2", completed: false },
    { id: 1, text: "Reschedule the dentist appointment", completed: false },
    { id: 2, text: "Prepare for CSC309 exam", completed: false },
    { id: 3, text: "Find term project partner", completed: true },
    { id: 4, text: "Learn React Hooks", completed: false },
];

function App() {
  const [todos, setTodos] = useState(seed);
  const addTodo = (text) => {
    setTodos((prev) => {
        
      const nextId = prev.length > 0 ? Math.max(...prev.map((t) => t.id)) + 1 : 0;

      return [...prev, { id: nextId, text: text, completed: false }];
    });
  };


  const toggleTodo = (id) => {
    setTodos((prev) => {
      const updated = prev.map((t) => {

        if (t.id === id) {
          return { id: t.id, text: t.text, completed: !t.completed };
        }
        return t;
      });
      return updated;
    });
  };
  const deleteTodo = (id) => {
    setTodos((prev) => prev.filter((t) => t.id !== id));
  };


  return (
    <div className="app">
      <h1>My ToDos</h1>
      <NewTodo onAdd={addTodo} />
      {todos.map((todo) => (
        <TodoItem

          key={todo.id}
          todo={todo}
          onToggle={toggleTodo}
          onDelete={deleteTodo}
        />
      ))}
    </div>
  );

}


export default App;
