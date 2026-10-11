// Small UX helpers shared across admin pages.
document.addEventListener("DOMContentLoaded", () => {
  // Auto-dismiss flash messages after a few seconds.
  document.querySelectorAll(".flash").forEach((el) => {
    setTimeout(() => { el.style.transition = "opacity .4s"; el.style.opacity = "0"; }, 4000);
  });

  // Click-to-copy on tracking links.
  document.querySelectorAll(".tracking-link").forEach((el) => {
    el.style.cursor = "pointer";
    el.title = "Click to copy";
    el.addEventListener("click", () => {
      navigator.clipboard.writeText(el.textContent.trim()).then(() => {
        const old = el.textContent;
        el.textContent = "Copied!";
        setTimeout(() => { el.textContent = old; }, 1000);
      });
    });
  });
});
