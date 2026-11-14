// Light / dark theme.
//
// Loaded in <head> without defer so it runs before the first paint: the saved
// choice is applied to <html> straight away, which is why there is no flash of
// the wrong palette. With no saved choice the operating system decides, and it
// keeps deciding as the OS switches, until someone clicks the switch.
(function () {
  const KEY = "soc-theme";
  const root = document.documentElement;
  const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function saved() {
    try {
      return localStorage.getItem(KEY);
    } catch (error) {
      // Private mode or a locked-down profile: fall back to the OS.
      return null;
    }
  }

  function systemTheme() {
    return darkQuery.matches ? "dark" : "light";
  }

  function paint(theme) {
    root.dataset.theme = theme;
    document.querySelectorAll("[data-theme-choice]").forEach((button) => {
      button.setAttribute("aria-pressed", button.dataset.themeChoice === theme ? "true" : "false");
    });
  }

  paint(saved() || systemTheme());

  // The buttons are in the body, which does not exist yet when this runs, so
  // the pressed state is applied again once the page is parsed.
  document.addEventListener("DOMContentLoaded", () => paint(root.dataset.theme));

  // Only follow the OS while nobody has chosen.
  darkQuery.addEventListener("change", () => {
    if (!saved()) paint(systemTheme());
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-theme-choice]");
    if (!button) return;
    const choice = button.dataset.themeChoice;
    try {
      localStorage.setItem(KEY, choice);
    } catch (error) {
      // Nothing to persist to; the choice still applies to this page.
    }
    paint(choice);
  });
})();
