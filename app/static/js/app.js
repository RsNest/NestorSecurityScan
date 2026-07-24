// Theme switcher: reads cookie, applies, persists toggle.
(function () {
  const KEY = "nss_theme";
  function getCookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
  }
  function setCookie(name, value) {
    document.cookie = name + "=" + encodeURIComponent(value) + ";path=/;max-age=31536000;samesite=lax";
  }
  function apply(theme) {
    const t = theme || "system";
    let resolved = t;
    if (t === "system") {
      resolved = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    }
    document.documentElement.setAttribute("data-theme", resolved);
    document.documentElement.setAttribute("data-theme-pref", t);
  }
  function current() {
    return document.documentElement.getAttribute("data-theme-pref") || "system";
  }
  function cycle() {
    const order = ["system", "light", "dark"];
    const next = order[(order.indexOf(current()) + 1) % order.length];
    setCookie(KEY, next);
    apply(next);
    const btn = document.getElementById("themeToggle");
    if (btn) btn.textContent = label(next);
  }
  function label(pref) {
    if (pref === "light") return "☀";
    if (pref === "dark") return "☾";
    return "◐";
  }
  const initial = getCookie(KEY) || "system";
  apply(initial);
  document.addEventListener("DOMContentLoaded", function () {
    const btn = document.getElementById("themeToggle");
    if (btn) {
      btn.textContent = label(current());
      btn.addEventListener("click", cycle);
      btn.title = "Тема: " + current();
    }
    if (window.matchMedia) {
      window
        .matchMedia("(prefers-color-scheme: dark)")
        .addEventListener("change", function () {
          if (current() === "system") apply("system");
        });
    }
  });
})();
