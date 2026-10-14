"""
Rotas Principais da Aplicação.
Contém a Página Interna (Dashboard) protegida pelo controle de acesso (@login_required).
"""

from flask import Blueprint, render_template, redirect, url_for, session
from app.security import login_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Redirecionamento inicial baseado no status de autenticação."""
    if session.get("authenticated"):
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Página interna protegida.
    Acessível exclusivamente após validação criptográfica de credenciais e sessão ativa.
    """
    user_data = session.get("user", {})
    login_time = session.get("login_time", "Não registrado")

    # Lista das 5 defesas ativas da OWASP Top 10 implementadas na aplicação
    owasp_defenses = [
        {
            "id": "A01:2025",
            "name": "Broken Access Control",
            "status": "Ativo & Mitigado",
            "badge": "badge-success",
            "description": (
                "Controle estrito de acesso através do decorador @login_required, garantindo que rotas "
                "internas sejam inacessíveis a usuários anônimos e sessões sejam purgadas no logout."
            ),
            "implementation": "app/security.py (login_required), app/auth.py (logout session.clear)"
        },
        {
            "id": "A02:2025",
            "name": "Cryptographic Failures",
            "status": "Ativo & Mitigado",
            "badge": "badge-success",
            "description": (
                "Zero armazenamento de senhas em texto puro. Utilização de PBKDF2-HMAC-SHA256 com salt "
                "criptográfico (600.000 iterações) e cookies assinados com flags HTTPOnly e SameSite."
            ),
            "implementation": "app/security.py (hash_password, verify_password)"
        },
        {
            "id": "A03:2025",
            "name": "Injection & XSS",
            "status": "Ativo & Mitigado",
            "badge": "badge-success",
            "description": (
                "Sanitização de parâmetros de formulário, escape automático via Jinja2 contra Cross-Site "
                "Scripting (XSS) e Content-Security-Policy (CSP) estrito bloqueando scripts externos não autorizados."
            ),
            "implementation": "app/security.py (validate_username, apply_security_headers CSP)"
        },
        {
            "id": "A05:2025",
            "name": "Security Misconfiguration",
            "status": "Ativo & Mitigado",
            "badge": "badge-success",
            "description": (
                "Blindagem de cabeçalhos HTTP (X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
                "Referrer-Policy), supressão de banners do servidor e tratamento genérico de erros sem vazamento."
            ),
            "implementation": "app/security.py (apply_security_headers), app/__init__.py (error handlers)"
        },
        {
            "id": "A07:2025",
            "name": "Identification & Authentication Failures",
            "status": "Ativo & Mitigado",
            "badge": "badge-success",
            "description": (
                "Mecanismo de Rate Limiting que bloqueia tentativas repetidas de login (anti-força bruta), "
                "mensagens genéricas de falha (anti-enumeração) e renovação de sessão após autenticação."
            ),
            "implementation": "app/security.py (InMemoryRateLimiter), app/auth.py (anti-enumeration & session reset)"
        }
    ]

    return render_template(
        "dashboard.html",
        user=user_data,
        login_time=login_time,
        owasp_defenses=owasp_defenses
    )
