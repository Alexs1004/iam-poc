document.addEventListener("DOMContentLoaded", () => {
  const buttons = Array.from(document.querySelectorAll("[data-admin-target]"));
  const panes = Array.from(document.querySelectorAll("[data-admin-section]"));

  if (!buttons.length || !panes.length) {
    return;
  }

  const activate = (target) => {
    panes.forEach((pane) => {
      const isTarget = pane.dataset.adminSection === target;
      pane.hidden = !isTarget;
    });

    buttons.forEach((button) => {
      const isActive = button.dataset.adminTarget === target;
      button.classList.toggle("is-active", isActive);
      button.setAttribute("aria-selected", isActive ? "true" : "false");
      button.setAttribute("tabindex", isActive ? "0" : "-1");
    });
  };

  buttons.forEach((button) => {
    button.addEventListener("click", () => activate(button.dataset.adminTarget));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
        return;
      }
      event.preventDefault();
      const currentIndex = buttons.indexOf(button);
      let nextIndex = currentIndex;
      if (event.key === "ArrowLeft") {
        nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
      } else if (event.key === "ArrowRight") {
        nextIndex = (currentIndex + 1) % buttons.length;
      } else if (event.key === "Home") {
        nextIndex = 0;
      } else if (event.key === "End") {
        nextIndex = buttons.length - 1;
      }
      const nextButton = buttons[nextIndex];
      activate(nextButton.dataset.adminTarget);
      nextButton.focus();
    });
  });

  const defaultButton = buttons.find((button) => button.classList.contains("is-active")) || buttons[0];
  if (defaultButton) {
    activate(defaultButton.dataset.adminTarget);
  }
});
