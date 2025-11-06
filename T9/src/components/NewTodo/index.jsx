import "./style.css";
import { useState } from "react";

function NewTodo(props) {
  const [text, setText] = useState("");

  const handleClick = () => {
    const trimmed = text.trim();

    if (trimmed === "") {
      return;
    }

    props.onAdd(trimmed);

    setText("");
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter") {
      handleClick();
    }
  };

  return (
    <div className='new-todo row'>
      <input
        type="text"
        placeholder="Enter a new task"
        value={text}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={handleKeyDown}
      />
      <button type="button" onClick={handleClick}>
        +
      </button>
    </div>
  );
}

export default NewTodo;
