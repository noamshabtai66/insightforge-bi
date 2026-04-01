/* InsightForge BI — Main JS utilities */

function dismissAlert(alert) {
  alert.style.transition = 'opacity 0.4s';
  alert.style.opacity = '0';
  setTimeout(() => alert.remove(), 400);
}

// Auto-dismiss flash messages after 5 seconds; inject close button
document.addEventListener('DOMContentLoaded', () => {
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach((alert) => {
    // Inject ✕ close button
    const btn = document.createElement('button');
    btn.textContent = '×';
    btn.className = 'alert-close';
    btn.setAttribute('aria-label', 'Dismiss');
    btn.addEventListener('click', () => dismissAlert(alert));
    alert.appendChild(btn);

    // Auto-dismiss after 5 s
    setTimeout(() => dismissAlert(alert), 5000);
  });
});
