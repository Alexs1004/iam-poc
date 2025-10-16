document.addEventListener("DOMContentLoaded", () => {
  const header = document.querySelector("[data-nav]");
  const toggle = header?.querySelector(".nav-toggle");
  const nav = header?.querySelector(".nav-actions");

  if (!header || !toggle || !nav) {
    return;
  }

  const closeNav = () => {
    nav.classList.remove("is-open");
    toggle.setAttribute("aria-expanded", "false");
  };

  toggle.addEventListener("click", () => {
    const isOpen = nav.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", String(isOpen));
  });

  nav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", closeNav);
  });

  window.addEventListener("resize", () => {
    if (window.matchMedia("(min-width: 900px)").matches) {
      closeNav();
    }
  });
});
