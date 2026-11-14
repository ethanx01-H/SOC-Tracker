// A calendar popover for the From / To fields.
//
// The browser's own date input cannot be styled, and its display format follows
// the browser locale rather than the page. This replaces it with a small card in
// the app's own look: month header with chevrons, a weekday row, and the day
// grid. The field itself stays a plain dd/mm/yyyy text box, so typing still
// works and the form still submits without any of this.
//
// The title in the header is clickable: day grid -> month grid -> year grid, so
// jumping three years back is two clicks instead of thirty-six.
(function () {
  const MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
  ];
  const WEEKDAYS = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];

  const pad = (value) => String(value).padStart(2, "0");

  function toIso(text) {
    const match = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec((text || "").trim());
    if (!match) return "";
    const day = Number(match[1]);
    const month = Number(match[2]);
    const year = Number(match[3]);
    const parsed = new Date(year, month - 1, day);
    if (parsed.getFullYear() !== year || parsed.getMonth() !== month - 1 || parsed.getDate() !== day) return "";
    return `${year}-${pad(month)}-${pad(day)}`;
  }

  function fromIso(iso) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec((iso || "").trim());
    if (!match) return null;
    return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  }

  function display(date) {
    return `${pad(date.getDate())}/${pad(date.getMonth() + 1)}/${date.getFullYear()}`;
  }

  function sameDay(a, b) {
    return a && b && a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  }

  let pop = null;
  let active = null;          // the text input the popover belongs to
  let view = "day";           // day | month | year
  let cursor = new Date();    // the month (or year) being shown

  function build() {
    pop = document.createElement("div");
    pop.className = "dp";
    pop.setAttribute("role", "dialog");
    pop.setAttribute("aria-label", "Choose a date");
    pop.hidden = true;
    pop.innerHTML = `
      <div class="dp-head">
        <button type="button" class="dp-nav" data-dp-prev aria-label="Previous">&lsaquo;</button>
        <button type="button" class="dp-title" data-dp-title></button>
        <button type="button" class="dp-nav" data-dp-next aria-label="Next">&rsaquo;</button>
      </div>
      <div class="dp-weekdays"></div>
      <div class="dp-grid"></div>
      <div class="dp-foot">
        <button type="button" class="dp-action" data-dp-today>Today</button>
        <button type="button" class="dp-action" data-dp-clear>Clear</button>
      </div>`;
    document.body.appendChild(pop);

    pop.querySelector("[data-dp-prev]").addEventListener("click", () => shift(-1));
    pop.querySelector("[data-dp-next]").addEventListener("click", () => shift(1));
    pop.querySelector("[data-dp-title]").addEventListener("click", () => {
      view = view === "day" ? "month" : view === "month" ? "year" : "day";
      render();
    });
    pop.querySelector("[data-dp-today]").addEventListener("click", () => choose(new Date()));
    pop.querySelector("[data-dp-clear]").addEventListener("click", () => {
      if (!active) return;
      active.value = "";
      active.dataset.autofilled = "";
      active.dispatchEvent(new Event("change", { bubbles: true }));
      close();
    });
  }

  function shift(step) {
    if (view === "day") {
      cursor = new Date(cursor.getFullYear(), cursor.getMonth() + step, 1);
    } else if (view === "month") {
      cursor = new Date(cursor.getFullYear() + step, cursor.getMonth(), 1);
    } else {
      cursor = new Date(cursor.getFullYear() + step * 12, cursor.getMonth(), 1);
    }
    render();
  }

  function position() {
    if (!active || !pop) return;
    const rect = active.getBoundingClientRect();
    const width = pop.offsetWidth || 288;
    const height = pop.offsetHeight || 320;
    let left = Math.max(12, Math.min(rect.right - width, window.innerWidth - width - 12));
    let top = rect.bottom + 6;
    if (top + height > window.innerHeight - 12) {
      top = Math.max(12, rect.top - height - 6);
    }
    pop.style.left = left + "px";
    pop.style.top = top + "px";
  }

  function render() {
    if (!pop || !active) return;

    const title = pop.querySelector("[data-dp-title]");
    if (view === "day") title.textContent = `${MONTHS[cursor.getMonth()]} ${cursor.getFullYear()}`;
    else if (view === "month") title.textContent = String(cursor.getFullYear());
    else {
      const decade = Math.floor(cursor.getFullYear() / 12) * 12;
      title.textContent = `${decade} – ${decade + 11}`;
    }

    const weekdays = pop.querySelector(".dp-weekdays");
    const grid = pop.querySelector(".dp-grid");
    weekdays.textContent = "";
    grid.textContent = "";
    grid.className = "dp-grid" + (view === "day" ? "" : " dp-grid-wide");

    const selected = fromIso(toIso(active.value));
    const today = new Date();

    if (view === "day") {
      WEEKDAYS.forEach((name) => {
        const cell = document.createElement("span");
        cell.className = "dp-weekday";
        cell.textContent = name;
        weekdays.appendChild(cell);
      });

      const first = new Date(cursor.getFullYear(), cursor.getMonth(), 1);
      const lead = (first.getDay() + 6) % 7;          // Monday-first
      const start = new Date(first.getFullYear(), first.getMonth(), 1 - lead);
      const daysInMonth = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0).getDate();
      // Five weeks is enough for most months; drawing a sixth only to fill it
      // with next month made the card taller than the month needs.
      const cells = Math.ceil((lead + daysInMonth) / 7) * 7;

      for (let index = 0; index < cells; index += 1) {
        const day = new Date(start.getFullYear(), start.getMonth(), start.getDate() + index);
        const button = document.createElement("button");
        button.type = "button";
        button.className = "dp-day";
        button.textContent = String(day.getDate());
        if (day.getMonth() !== cursor.getMonth()) button.classList.add("is-out");
        if (sameDay(day, today)) button.classList.add("is-today");
        if (sameDay(day, selected)) button.classList.add("is-selected");
        button.setAttribute("aria-label", display(day));
        if (sameDay(day, selected)) button.setAttribute("aria-current", "date");
        button.addEventListener("click", () => choose(day));
        grid.appendChild(button);
      }
    } else if (view === "month") {
      MONTHS.forEach((name, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "dp-cell";
        button.textContent = name.slice(0, 3);
        button.title = name;
        if (selected && selected.getFullYear() === cursor.getFullYear() && selected.getMonth() === index) {
          button.classList.add("is-selected");
        }
        button.addEventListener("click", () => {
          cursor = new Date(cursor.getFullYear(), index, 1);
          view = "day";
          render();
        });
        grid.appendChild(button);
      });
    } else {
      const decade = Math.floor(cursor.getFullYear() / 12) * 12;
      for (let offset = 0; offset < 12; offset += 1) {
        const year = decade + offset;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "dp-cell";
        button.textContent = String(year);
        if (selected && selected.getFullYear() === year) button.classList.add("is-selected");
        button.addEventListener("click", () => {
          cursor = new Date(year, cursor.getMonth(), 1);
          view = "month";
          render();
        });
        grid.appendChild(button);
      }
    }

    position();
  }

  function choose(date) {
    if (!active) return;
    active.value = display(date);
    active.dataset.autofilled = "";
    // The rest of the filter (partner field, URL, results) listens for change.
    active.dispatchEvent(new Event("change", { bubbles: true }));
    close();
  }

  function open(input) {
    if (!pop) build();
    active = input;
    view = "day";
    const current = fromIso(toIso(input.value));
    cursor = current ? new Date(current.getFullYear(), current.getMonth(), 1) : new Date();
    pop.hidden = false;
    render();
  }

  function close() {
    if (pop) pop.hidden = true;
    active = null;
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-date-open]");
    if (trigger) {
      const input = trigger.closest(".date-input").querySelector("[data-date-text]");
      event.preventDefault();
      if (active === input) close();
      else open(input);
      return;
    }

    const clear = event.target.closest("[data-date-clear]");
    if (clear) {
      event.preventDefault();
      const input = clear.closest(".date-input").querySelector("[data-date-text]");
      input.value = "";
      input.dataset.autofilled = "";
      input.dispatchEvent(new Event("change", { bubbles: true }));
      close();
      return;
    }

    if (!pop || pop.hidden) return;
    // Some clicks re-render the grid, which detaches the clicked button before
    // the event reaches the document. composedPath() still remembers where the
    // click started, so a click inside the card does not close the card.
    if (event.composedPath().includes(pop)) return;
    close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });

  window.addEventListener("resize", position);
  window.addEventListener("scroll", position, true);

  // The clear button only makes sense while there is something to clear.
  function syncClearButtons() {
    document.querySelectorAll(".date-input").forEach((wrap) => {
      const input = wrap.querySelector("[data-date-text]");
      const clear = wrap.querySelector("[data-date-clear]");
      if (!input || !clear) return;
      clear.hidden = !input.value.trim();
    });
  }

  document.addEventListener("change", syncClearButtons);
  document.addEventListener("alerts:refreshed", syncClearButtons);
  document.addEventListener("DOMContentLoaded", syncClearButtons);
  syncClearButtons();
})();
