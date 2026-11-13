// Image popup for evidence thumbnails.
//
// Driven by a class, not by the URL hash: a hash-based popup pushed a history
// entry on every open, so pressing Back from the alert list landed on
// /alerts/9/#preview-4 and reopened the image. Nothing here touches history,
// so navigating away and back leaves the popup closed.
(function () {
  "use strict";

  function closeAll() {
    var open = document.querySelectorAll(".lightbox.is-open");
    for (var i = 0; i < open.length; i += 1) {
      open[i].classList.remove("is-open");
    }
    document.body.classList.remove("lightbox-open");
  }

  function open(id) {
    var box = document.getElementById(id);
    if (!box) {
      return;
    }
    closeAll();
    box.classList.add("is-open");
    document.body.classList.add("lightbox-open");
  }

  document.addEventListener("click", function (event) {
    var opener = event.target.closest(".evidence-open");
    if (opener) {
      event.preventDefault();
      open(opener.getAttribute("data-preview"));
      return;
    }
    if (event.target.closest(".lightbox-close") || event.target.classList.contains("lightbox-backdrop")) {
      event.preventDefault();
      closeAll();
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeAll();
    }
  });

  // Leaving the page closes the popup, so returning to it (including through the
  // browser's back-forward cache, which restores the DOM as it was) shows the
  // ticket with the popup shut.
  window.addEventListener("pagehide", closeAll);
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      closeAll();
    }
  });

  // A #preview- fragment left in a bookmark or an old history entry must not
  // pop an image open on load.
  if (window.location.hash.indexOf("#preview-") === 0) {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
})();
