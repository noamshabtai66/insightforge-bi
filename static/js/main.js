/* InsightForge BI — Main JS utilities */

function dismissAlert(alert) {
  alert.style.transition = 'opacity 0.4s';
  alert.style.opacity = '0';
  setTimeout(() => alert.remove(), 400);
}

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages after 5 seconds; inject close button
  document.querySelectorAll('.alert').forEach((alert) => {
    const btn = document.createElement('button');
    btn.textContent = '×';
    btn.className = 'alert-close';
    btn.setAttribute('aria-label', 'Dismiss');
    btn.addEventListener('click', () => dismissAlert(alert));
    alert.appendChild(btn);
    setTimeout(() => dismissAlert(alert), 5000);
  });

  // Mobile hamburger nav toggle
  const hamburger = document.getElementById('nav-hamburger');
  const navLinks = document.getElementById('nav-links');
  if (hamburger && navLinks) {
    hamburger.addEventListener('click', () => {
      const isOpen = navLinks.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
  }
});
