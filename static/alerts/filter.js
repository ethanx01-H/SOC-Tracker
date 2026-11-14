// Filtering without a page reload.
//
// The form used to submit a GET request, so every filter click reloaded the
// whole page and jumped back to the top. Now the same URL answers with just the
// results markup, the container is swapped in place, and the address bar is
// updated with replaceState so Back still goes to the previous page instead of
// walking through every keystroke.
(function () {
  const form = document.querySelector("[data-filter-form]");
  const results = document.getElementById("alert-results");
  if (!form || !results) return;

  let controller = null;
  let timer = null;

  function buildUrl() {
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
      // The granularity is inferred from the value itself, so it stays out of
      // the URL and a link stays readable: ?from=2026-10&to=2026-10.
      if (key === "unit") return;
      const text = String(value).trim();
      if (text) params.append(key, text);
    });
    const query = params.toString();
    return location.pathname + (query ? "?" + query : "");
  }

  function applyDateType(type) {
    form.querySelectorAll("input[name='from'], input[name='to']").forEach((input) => {
      input.type = type;
      input.value = "";
      input.dataset.autofilled = "";
      if (type === "number") {
        input.min = "2000";
        input.max = "2100";
        input.step = "1";
        input.placeholder = "2026";
      } else {
        ["min", "max", "step"].forEach((name) => input.removeAttribute(name));
        input.placeholder = "";
      }
    });
  }

  function syncRangePills() {
    // The pills live outside the swapped container, so their highlight has to be
    // corrected here: otherwise "All time" stays lit while a date range is active.
    const params = new URLSearchParams(location.search);
    const custom = params.get("from") || params.get("to");
    const range = custom ? null : (params.get("range") || "all");
    document.querySelectorAll(".range-pill").forEach((pill) => {
      const value = new URL(pill.getAttribute("href"), location.origin).searchParams.get("range");
      pill.classList.toggle("active", !custom && value === range);
    });
  }

  async function refresh(url) {
    if (controller) controller.abort();
    controller = new AbortController();
    results.classList.add("is-loading");
    try {
      const response = await fetch(url, {
        headers: { "X-Partial": "1" },
        credentials: "same-origin",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      results.innerHTML = await response.text();
      history.replaceState(null, "", url);
      syncRangePills();
      document.dispatchEvent(new CustomEvent("alerts:refreshed"));
    } catch (error) {
      if (error.name === "AbortError") return;
      // Showing results that no longer match the box is worse than a reload.
      window.location.href = url;
    } finally {
      results.classList.remove("is-loading");
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    clearTimeout(timer);
    refresh(buildUrl());
  });

  function syncPartner(input) {
    // Picking a period in one field fills the other with the same period, so a
    // month or a year is one click rather than two. A value the user typed
    // themselves is kept — only an auto-filled partner is replaced, and the two
    // bounds are always kept in order.
    const other = form.querySelector(input.name === "from" ? "input[name='to']" : "input[name='from']");
    if (!other || !input.value) return;
    const autofilled = other.dataset.autofilled === "1";
    if (!other.value || autofilled) {
      other.value = input.value;
      other.dataset.autofilled = "1";
      return;
    }
    if (input.name === "from" && other.value < input.value) {
      other.value = input.value;
    } else if (input.name === "to" && other.value > input.value) {
      other.value = input.value;
    }
  }

  form.addEventListener("change", (event) => {
    // Day, month and year all share the two fields; the input type is what
    // changes, so the same change event covers all three.
    if (event.target.matches("select:not([data-date-unit]), input[name='from'], input[name='to']")) {
      if (event.target.name === "from" || event.target.name === "to") {
        // This field was edited by hand, so it is no longer ours to overwrite.
        event.target.dataset.autofilled = "";
        syncPartner(event.target);
      }
      refresh(buildUrl());
    }
  });

  const unitSelect = form.querySelector("[data-date-unit]");
  if (unitSelect) {
    unitSelect.addEventListener("change", () => {
      const type = { day: "date", month: "month", year: "number" }[unitSelect.value] || "date";
      applyDateType(type);
      // The old value was written at a different granularity, so it is dropped
      // rather than reinterpreted: 20 Oct as a year means nothing.
      refresh(buildUrl());
    });
  }

  form.addEventListener("input", (event) => {
    if (!event.target.matches("input[name='q']")) return;
    clearTimeout(timer);
    timer = setTimeout(() => refresh(buildUrl()), 300);
  });

  // The pager lives inside the swapped container, so listen on the document.
  document.addEventListener("click", (event) => {
    const clear = event.target.closest("#alert-results [data-clear]");
    if (clear) {
      event.preventDefault();
      form.querySelector("input[name='q']").value = "";
      form.querySelectorAll("select:not([data-date-unit])").forEach((select) => { select.value = ""; });
      if (unitSelect) unitSelect.value = "day";
      applyDateType("date");
      refresh(location.pathname);
      return;
    }
    const link = event.target.closest("#alert-results .pager a");
    if (!link) return;
    event.preventDefault();
    refresh(link.getAttribute("href"));
  });
})();
