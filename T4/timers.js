/* global list of timers */
var timers = [];
var next_id = 1;

function update_stats() {
    let num_active_timers = document.querySelector("#num_active_timers");
    /* TODO: Find the DOM nodes as JS objects (Elements)
    */
    let num_expired_timers = document.querySelector("#num_expired_timers");
    let avg_remain_time = document.querySelector("#avg_remain_time");


    /* TODO: Complete these stats calculations. 
    Hint: use Array.reduce on timers;
    */
    let num_expired = 0;
    let num_active = 0;
    let avg_seconds = 0;

    num_active_timers.innerHTML = num_active;
    num_expired_timers.innerHTML = num_expired;
    avg_remain_time.innerHTML = Math.ceil(avg_seconds);
}

class Timer {
    constructor(minutes, seconds, update, remove) {
        this.id = next_id;
        next_id += 1;
        
        /* TODO: Complete the constructor and start a periodic callback
         * using setInterval to update the timer value once every 1 second.
         * When the timer reaches 0, the countdown should stop. */
        this.remaining = minutes * 60 + seconds;
        this.update = update;
        this.remove = remove;

        
        this.update(Math.floor(this.remaining / 60), this.remaining % 60);

        this.interval = setInterval(() => {
          if (this.remaining > 0) { this.remaining--; this.update(Math.floor(this.remaining / 60), this.remaining % 60);

        }else { clearInterval(this.interval); }

        update_stats();

    }, 1000);

    /* TODO: Add other methods as you see fit */
}

extend(seconds) {
        this.remaining += seconds;
        if (!this.interval) {
            this.interval = setInterval(() => {
                if (this.remaining > 0) {
                    this.remaining--;
                    this.update(Math.floor(this.remaining / 60), this.remaining % 60);
                } else {
                    clearInterval(this.interval);
                    this.interval = null;
                }
                update_stats();
            }, 1000);
        }
    }
}

function create_timer(event, form)
{
    /* we don't actually want to submit a request */
    event.preventDefault();

    let name = form["name"].value.trim();
    let minutes = parseInt(form["minutes"].value);
    let seconds = parseInt(form["seconds"].value);
    let error = form.getElementsByClassName("error")[0];

    if (minutes < 0 || seconds < 0 || minutes * 60 + seconds <= 0) {
        error.innerHTML = "value must be greater than zero.";
        return false;
    }
    else {
        error.innerHTML = "";
    }

    let container = document.createElement("details");
    const new_id = next_id;
    const remove = (_e) => {
        timers = timers.filter((elem) => elem.id !== new_id);
        container.remove(); 
    };

    let timer = new Timer(
        minutes,
        seconds,
        (m, s) => {
            let minutes = Array.from(container.getElementsByClassName("minutes"));
            let seconds = Array.from(container.getElementsByClassName("seconds"));
            minutes.forEach((elem, _i) => { elem.innerHTML = m; });
            seconds.forEach((elem, _i) => { elem.innerHTML = String(s).padStart(2, "0"); });
        },
        remove
    );

    const seconds_padded = String(seconds).padStart(2, "0");
    container.innerHTML = `
        <summary>${name}<a href="#">&#x274c;</a></summary>
        <div>
        <span class="minutes">${minutes}</span>:<span class="seconds">${seconds_padded}</span>
        </div>
    `;
    container.setAttribute("open", "");
    let anchors = Array.from(container.getElementsByTagName("a"));
    anchors.forEach((elem, _i) => { elem.addEventListener("click", remove) });

    let main = document.getElementById("main");
    main.appendChild(container);
    timers.push(timer);

    return false;
}

function extend_all_timers(event, form) {
    /* we don't actually want to submit a request */
    event.preventDefault();
    let seconds = parseInt(form["seconds"].value);
    let error = form.getElementsByClassName("error")[0];
    if (seconds <= 0) {
        error.innerHTML = "value must be greater than zero.";
        return false;
    }
    else {
        error.innerHTML = "";
    }

    /* TODO: Extend all timers' values by `seconds`. Hint: use Array.forEach. */
    timers.forEach(t => t.extend(seconds));
    update_stats();
    return false;
}

function clear_expired_timers(event) {
    event.preventDefault();
    timers.filter(t => t.remaining <= 0).forEach(t => t.remove());
    update_stats();
    /* TODO: Remove all expired timers from `timers` by calling the `remove` 
     * closure passed to their constructors. Hint: use Array.filter. */
}