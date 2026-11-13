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
      const text = String(value).trim();
      if (text) params.append(key, text);
    });
    const query = params.toString();
    return location.pathname + (query ? "?" + query : "");
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

  form.addEventListener("change", (event) => {
    if (event.target.matches("select")) refresh(buildUrl());
  });

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
      form.querySelectorAll("select").forEach((select) => { select.value = ""; });
      refresh(location.pathname);
      return;
    }
    const link = event.target.closest("#alert-results .pager a");
    if (!link) return;
    event.preventDefault();
    refresh(link.getAttribute("href"));
  });
})();
