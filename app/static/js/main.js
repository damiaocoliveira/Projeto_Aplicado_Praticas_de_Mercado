/**
 * Client-side script for SecureShield application.
 * Follows CSP directives: zero inline scripts or unsafe evals.
 */
document.addEventListener("DOMContentLoaded", function () {
    // Alternância de visibilidade da senha no login
    var toggleBtn = document.getElementById("togglePassword");
    var passwordInput = document.getElementById("password");

    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", function () {
            var isPassword = passwordInput.getAttribute("type") === "password";
            passwordInput.setAttribute("type", isPassword ? "text" : "password");
            toggleBtn.textContent = isPassword ? "🙈" : "👁️";
        });
    }

    // Prevenção de múltiplos envios concorrentes (Anti-Double Submit)
    var loginForm = document.getElementById("loginForm");
    var btnLogin = document.getElementById("btnLogin");

    if (loginForm && btnLogin) {
        loginForm.addEventListener("submit", function () {
            btnLogin.setAttribute("disabled", "disabled");
            btnLogin.style.opacity = "0.7";
            btnLogin.style.cursor = "not-allowed";
        });
    }
});
