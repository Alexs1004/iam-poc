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

  document.querySelectorAll("td.role-cell").forEach((cell) => {
    const roles = cell.querySelectorAll(".role-chip");
    if (roles.length === 1) {
      cell.classList.remove("role-cell");
    }
  });

  const moverForm = document.querySelector("[data-mover-form]");
  if (moverForm) {
    const userSelect = moverForm.querySelector("[data-mover-user]");
    const roleSelect = moverForm.querySelector("[data-role-select]");
    const roleDisplay = moverForm.querySelector("[data-role-display]");
    const roleHidden = moverForm.querySelector("[data-role-hidden]");
    const roleLabel = moverForm.querySelector("[data-role-label]");
    const targetRoleSelect = moverForm.querySelector("[data-role-target]");
    const submitButton = moverForm.querySelector("[data-mover-submit]");

    const updateTargetRoleOptions = (currentRole) => {
      if (!targetRoleSelect) return;
      
      const allOptions = Array.from(targetRoleSelect.querySelectorAll("option"));
      const currentValue = targetRoleSelect.value;
      
      allOptions.forEach((option) => {
        option.disabled = option.value === currentRole;
        option.hidden = option.value === currentRole;
      });
      
      if (currentValue === currentRole) {
        const firstAvailable = allOptions.find(opt => opt.value !== currentRole);
        if (firstAvailable) {
          targetRoleSelect.value = firstAvailable.value;
        }
      }
    };

    const setRoleControls = (roles) => {
      const uniqueRoles = Array.from(new Set((roles || []).map((role) => (role || "").toString()))).filter(Boolean);

      if (uniqueRoles.length > 1) {
        roleSelect.hidden = false;
        roleSelect.disabled = false;
        roleSelect.required = true;
        roleSelect.name = "source_role";
        roleSelect.innerHTML = "";
        uniqueRoles.forEach((role) => {
          const option = document.createElement("option");
          option.value = role;
          option.textContent = role;
          roleSelect.append(option);
        });
        roleSelect.value = uniqueRoles[0];

        roleDisplay.hidden = true;
        roleDisplay.value = "";

        roleHidden.disabled = true;
        roleHidden.name = "";
        roleHidden.value = "";
        roleHidden.required = false;

        if (submitButton) {
          submitButton.disabled = false;
        }

        updateTargetRoleOptions(uniqueRoles[0]);

        if (roleLabel) {
          roleLabel.setAttribute("for", roleSelect.id);
        }
      } else {
        const roleName = uniqueRoles[0] || "";

        roleSelect.hidden = true;
        roleSelect.disabled = true;
        roleSelect.required = false;
        roleSelect.name = "";
        roleSelect.innerHTML = "";
        roleSelect.value = "";

        roleDisplay.hidden = false;
        roleDisplay.value = roleName || "Not assigned";

        const hasRole = Boolean(roleName);
        roleHidden.disabled = !hasRole;
        roleHidden.name = hasRole ? "source_role" : "";
        roleHidden.value = roleName;
        roleHidden.required = hasRole;

        if (submitButton) {
          submitButton.disabled = !hasRole;
        }

        updateTargetRoleOptions(roleName);

        if (roleLabel) {
          if (hasRole) {
            roleLabel.setAttribute("for", roleDisplay.id);
          } else {
            roleLabel.removeAttribute("for");
          }
        }
      }
    };

    const updateRolesForUser = () => {
      const option = userSelect?.selectedOptions?.[0];
      if (!option) {
        setRoleControls([]);
        return;
      }
      let roles = [];
      try {
        roles = JSON.parse(option.dataset.roles || "[]");
      } catch (error) {
        console.error("Failed to parse roles for", option.value, error);
        roles = [];
      }
      setRoleControls(roles);
    };

    if (userSelect && roleSelect && roleDisplay && roleHidden) {
      updateRolesForUser();
      userSelect.addEventListener("change", updateRolesForUser);
      
      // Update target role options when current role changes (for multi-role users)
      roleSelect.addEventListener("change", () => {
        updateTargetRoleOptions(roleSelect.value);
      });
    }
  }
});
