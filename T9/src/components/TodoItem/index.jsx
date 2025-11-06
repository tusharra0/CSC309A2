import "./style.css";
import trash from "./trash.webp";

function TodoItem(props) {
  const todo = props.todo;

  const handleToggle = () => {
    props.onToggle(todo.id);
  };

  const handleDelete = (event) => {
    event.preventDefault(); 
    props.onDelete(todo.id);
  };
  let spanClass = "";
  if (todo.completed === true) {
    spanClass = "completed";
  }

  return (
    <div className="todo-item row">
      <input
        type="checkbox"
        checked={todo.completed}
        onChange={handleToggle}
      />
      <span className={spanClass}>{todo.text}</span>
      <a href="#" onClick={handleDelete}>
        <img src={trash} alt="Delete" />
      </a>
    </div>
  );
}

export default TodoItem;