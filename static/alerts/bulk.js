// Bulk selection feedback.
//
// "Bulk action not work" usually meant: nothing told the analyst whether a tick
// had registered, and Apply looked live even with an empty selection. The button
// now stays disabled until something is selected, the count is visible, and one
// checkbox selects the visible page.
(function () {
  const form = document.querySelector("[data-bulk-form]");
  if (!form) return;

  const all = form.querySelector("[data-bulk-all]");
  const counter = form.querySelector("[data-bulk-count]");
  const apply = form.querySelector("[data-bulk-apply]");
  const rows = () => Array.from(form.querySelectorAll("[data-row-check]"));

  function sync() {
    const boxes = rows();
    const checked = boxes.filter((box) => box.checked).length;
    if (counter) counter.textContent = checked + " selected";
    if (apply) apply.disabled = checked === 0;
    if (all) {
      all.checked = boxes.length > 0 && checked === boxes.length;
      all.indeterminate = checked > 0 && checked < boxes.length;
    }
  }

  if (all) {
    all.addEventListener("change", () => {
      rows().forEach((box) => { box.checked = all.checked; });
      sync();
    });
  }

  form.addEventListener("change", (event) => {
    if (event.target.matches("[data-row-check]")) sync();
  });

  // The results are swapped in place by filter.js, so the ticks disappear with
  // them; keep the counter honest instead of showing a stale number.
  document.addEventListener("alerts:refreshed", sync);

  sync();
})();
