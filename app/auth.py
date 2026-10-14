"""
Blueprint de Autenticação (Login e Logout).
Contém mitigações diretas de:
- OWASP A01: Broken Access Control (Invalidação real de sessão no logout)
- OWASP A02: Cryptographic Failures (Validação segura de hash PBKDF2)
- OWASP A07: Identification and Authentication Failures (Rate limit, Anti-Enumeration, Proteção contra Session Fixation)
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.security import (
    USERS_DB,
    verify_password,
    validate_username,
    login_limiter
)

auth_bp = Blueprint("auth", __name__)


def is_safe_redirect_url(target: str) -> bool:
    """Garante que o redirecionamento pós-login não aponte para domínios externos (Anti-Open-Redirect)."""
    if not target:
        return False
    return target.startswith("/") and not target.startswith("//")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Tela e processamento seguro de Login."""
    # Se o usuário já está autenticado, redireciona diretamente para o Dashboard
    if session.get("authenticated") and "user" in session:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        # 1. Verificação de Bloqueio por Força Bruta (Rate Limiting)
        locked, remaining = login_limiter.is_locked(client_ip)
        if locked:
            flash(
                f"Muitas tentativas malsucedidas detectadas. Por segurança, tente novamente em {remaining} segundos.",
                "danger"
            )
            return render_template("login.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 2. Validação de formato de entrada (Sanitização)
        valid_user_fmt, _ = validate_username(username)
        user_record = USERS_DB.get(username) if valid_user_fmt else None

        # 3. Verificação de Hash Criptográfico
        # Mensagem genérica para prevenir Enumeração de Usuários (OWASP A07)
        generic_error = "Credenciais inválidas. Verifique seu usuário e senha."

        if not user_record or not verify_password(password, user_record["password_hash"]):
            is_now_locked, lock_time = login_limiter.record_failure(client_ip)
            if is_now_locked:
                flash(
                    f"Limite de tentativas excedido. Bloqueio preventivo ativado por {lock_time} segundos.",
                    "danger"
                )
                return render_template("login.html"), 429
            flash(generic_error, "danger")
            return render_template("login.html"), 401

        # 4. Sucesso na Autenticação
        login_limiter.record_success(client_ip)

        # 5. Prevenção de Fixação de Sessão (Session Fixation): Limpeza prévia
        session.clear()

        # 6. Estabelecimento de Sessão Segura
        session["authenticated"] = True
        session["user"] = {
            "id": user_record["id"],
            "username": user_record["username"],
            "name": user_record["name"],
            "email": user_record["email"],
            "role": user_record["role"],
        }
        session["login_time"] = datetime.now(timezone.utc).strftime("%d/%m/%Y às %H:%M:%S UTC")

        flash(f"Bem-vindo(a), {user_record['name']}! Autenticação realizada com sucesso.", "success")

        # 7. Redirecionamento seguro pós-login
        next_url = request.args.get("next")
        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Botão funcional de Logout: Destrói completamente a sessão do usuário."""
    user_name = session.get("user", {}).get("name", "Usuário")
    session.clear()
    flash(f"Sessão encerrada com segurança. Até logo, {user_name}!", "info")
    return redirect(url_for("auth.login"))
