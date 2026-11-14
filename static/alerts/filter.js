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

  // The fields are typed as dd/mm/yyyy, the way the team writes dates; the URL
  // and the server keep ISO (yyyy-mm-dd), so a link stays unambiguous.
  function toIso(text) {
    const match = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec((text || "").trim());
    if (!match) return "";
    const day = Number(match[1]);
    const month = Number(match[2]);
    const year = Number(match[3]);
    const parsed = new Date(year, month - 1, day);
    if (parsed.getFullYear() !== year || parsed.getMonth() !== month - 1 || parsed.getDate() !== day) return "";
    const pad = (value) => String(value).padStart(2, "0");
    return `${year}-${pad(month)}-${pad(day)}`;
  }

  function toDisplay(iso) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec((iso || "").trim());
    return match ? `${match[3]}/${match[2]}/${match[1]}` : "";
  }

  function nativeOf(textInput) {
    return textInput.parentElement.querySelector("[data-date-native]");
  }

  function setDate(textInput, iso) {
    textInput.value = iso ? toDisplay(iso) : "";
    const native = nativeOf(textInput);
    if (native) native.value = iso || "";
  }

  function buildUrl() {
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => {
      const text = String(value).trim();
      if (key === "from" || key === "to") {
        // Half-typed or impossible dates are dropped rather than sent as text.
        const iso = toIso(text);
        if (iso) params.append(key, iso);
        return;
      }
      if (text) params.append(key, text);
    });
    const query = params.toString();
    return location.pathname + (query ? "?" + query : "");
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
    // Picking a day in one field fills the other with the same day, so a single
    // day is one pick. A day the user typed themselves is kept, and the two
    // bounds are always kept in order.
    const other = form.querySelector(input.name === "from" ? "[data-date-text][name='to']" : "[data-date-text][name='from']");
    const mine = toIso(input.value);
    if (!other || !mine) return;
    const theirs = toIso(other.value);
    const autofilled = other.dataset.autofilled === "1";
    if (!theirs || autofilled) {
      setDate(other, mine);
      other.dataset.autofilled = "1";
      return;
    }
    if (input.name === "from" && theirs < mine) setDate(other, mine);
    else if (input.name === "to" && theirs > mine) setDate(other, mine);
  }

  form.addEventListener("change", (event) => {
    const target = event.target;

    // The browser's own calendar wrote an ISO day into the hidden input.
    if (target.matches("[data-date-native]")) {
      const text = target.parentElement.querySelector("[data-date-text]");
      if (!text) return;
      setDate(text, target.value);
      text.dataset.autofilled = "";
      syncPartner(text);
      refresh(buildUrl());
      return;
    }

    if (target.matches("select")) {
      refresh(buildUrl());
      return;
    }

    if (target.matches("[data-date-text]")) {
      const iso = toIso(target.value);
      if (target.value.trim() && !iso) {
        // Something like 31/02/2026 is not a day; clearing is clearer than
        // silently filtering by a different date.
        setDate(target, "");
        refresh(buildUrl());
        return;
      }
      setDate(target, iso);
      target.dataset.autofilled = "";
      syncPartner(target);
      refresh(buildUrl());
    }
  });

  form.addEventListener("input", (event) => {
    const target = event.target;

    if (target.matches("[data-date-text]")) {
      // Type the digits, get the slashes: 20102026 becomes 20/10/2026.
      const digits = target.value.replace(/\D/g, "").slice(0, 8);
      let masked = digits.slice(0, 2);
      if (digits.length >= 3) masked += "/" + digits.slice(2, 4);
      if (digits.length >= 5) masked += "/" + digits.slice(4, 8);
      if (target.value !== masked) target.value = masked;
      return;
    }

    if (!target.matches("input[name='q']")) return;
    clearTimeout(timer);
    timer = setTimeout(() => refresh(buildUrl()), 300);
  });

  // The pager lives inside the swapped container, so listen on the document.
  document.addEventListener("click", (event) => {
    const clear = event.target.closest("#alert-results [data-clear]");
    if (clear) {
      event.preventDefault();
      form.querySelector("input[name='q']").value = "";
      form.querySelectorAll("select").forEach((select) => { select.value = ""; });
      form.querySelectorAll("[data-date-text]").forEach((input) => setDate(input, ""));
      refresh(location.pathname);
      return;
    }
    const link = event.target.closest("#alert-results .pager a");
    if (!link) return;
    event.preventDefault();
    refresh(link.getAttribute("href"));
  });
})();
