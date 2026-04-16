/* InsightForge BI — Main JS utilities */

function dismissAlert(alert) {
  alert.style.transition = 'opacity 0.4s';
  alert.style.opacity = '0';
  setTimeout(() => alert.remove(), 400);
}

/**
 * Score a password and return { level, label } where level is one of
 * 'weak' | 'fair' | 'good' | 'strong'.
 */
function scorePassword(pw) {
  if (!pw) return null;
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  const levels = ['weak', 'fair', 'good', 'strong'];
  const labels = ['Weak', 'Fair', 'Good', 'Strong'];
  const idx = Math.min(score, 3);
  return { level: levels[idx], label: labels[idx] };
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

  // Password strength indicator (register page only)
  const pwInput   = document.getElementById('password');
  const pwWidget  = document.getElementById('pw-strength');
  const pwFill    = document.getElementById('pw-strength-fill');
  const pwLabel   = document.getElementById('pw-strength-label');
  if (pwInput && pwWidget && pwFill && pwLabel) {
    pwInput.addEventListener('input', () => {
      const result = scorePassword(pwInput.value);
      if (!result) {
        pwWidget.classList.remove('visible');
        return;
      }
      pwWidget.classList.add('visible');
      pwFill.className  = 'strength-fill ' + result.level;
      pwLabel.className = 'strength-label ' + result.level;
      pwLabel.textContent = result.label;
    });
  }
});
