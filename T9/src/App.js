import "./App.css";
import { useState } from "react";

// You can use this to seed your TODO list
const seed = [
    { id: 0, text: "Submit assignment 2", completed: false },
    { id: 1, text: "Reschedule the dentist appointment", completed: false },
    { id: 2, text: "Prepare for CSC309 exam", completed: false },
    { id: 3, text: "Find term project partner", completed: true },
    { id: 4, text: "Learn React Hooks", completed: false },
];

function App() {
  const [todos, setTodos] = useState([
    { id: 0, text: "Example todo", completed: false },
  ]);

  const toggleTodo = (id) => {
    const updated = todos.map((t) => {
      if (t.id === id) {
        return {
          id: t.id,
          text: t.text,
          completed: !t.completed,
        };
      } else {
        return t;
      }
    });

    setTodos(updated);
  };

  return (
    <div className="app">
      <h1>My ToDos</h1>

      {todos.map((todo) => (
        <div key={todo.id}>
          <input
            type="checkbox"
            checked={todo.completed}
            onChange={() => toggleTodo(todo.id)}
          />
          <span>{todo.text}</span>
        </div>
      ))}
    </div>
  );
}

export default App;
