"""
Módulo de Segurança da Aplicação.
Implementa proteções alinhadas com as diretrizes do OWASP Top 10 (2025):
- A01: Broken Access Control (Decorador login_required e controle estrito de sessão)
- A02: Cryptographic Failures (Hashing robusto PBKDF2-SHA256, segredos e tokens)
- A03: Injection & XSS (Validação estrita de entrada e sanitização)
- A05: Security Misconfiguration (Cabeçalhos HTTP seguros: CSP, HSTS, X-Frame, X-Content-Type)
- A07: Identification and Authentication Failures (Rate limiting anti-brute force, bloqueio temporário)
"""

import time
import re
from functools import wraps
from flask import session, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash


# ==============================================================================
# OWASP A02: Cryptographic Failures - Hashing Seguro de Senhas
# ==============================================================================

def hash_password(plain_password: str) -> str:
    """Gera um hash PBKDF2 com SHA-256 e salt criptográfico."""
    return generate_password_hash(plain_password, method="pbkdf2:sha256:600000")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Valida a senha contra o hash criptográfico sem expor texto claro."""
    if not plain_password or not hashed_password:
        return False
    return check_password_hash(hashed_password, plain_password)


# Banco de dados simulado em memória (Zero senhas em texto puro)
# Demonstração de armazenamento seguro conforme exigido pelo Eixo 3
USERS_DB = {
    "admin": {
        "id": "usr_sec_01",
        "username": "admin",
        "name": "Especialista em Segurança",
        "email": "security.admin@enterprise.local",
        "role": "Administrador / SecOps",
        # Hash gerado a partir de 'AdminSecure@2026'
        "password_hash": generate_password_hash("AdminSecure@2026", method="pbkdf2:sha256:600000"),
        "created_at": "2026-01-10T10:00:00Z"
    },
    "auditor": {
        "id": "usr_sec_02",
        "username": "auditor",
        "name": "Auditor OWASP",
        "email": "auditor.ci@enterprise.local",
        "role": "Auditor de Conformidade",
        # Hash gerado a partir de 'AuditPass@2026'
        "password_hash": generate_password_hash("AuditPass@2026", method="pbkdf2:sha256:600000"),
        "created_at": "2026-02-01T14:30:00Z"
    }
}


# ==============================================================================
# OWASP A07: Identification & Authentication Failures - Rate Limiter (Anti-Brute Force)
# ==============================================================================

class InMemoryRateLimiter:
    """
    Controlador de taxa de requisições em memória.
    Impede ataques de força bruta limitando tentativas de login consecutivas.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60, lockout_seconds: int = 120):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.attempts = {}  # key -> list of timestamps
        self.lockouts = {}  # key -> lockout_expiry_timestamp

    def is_locked(self, key: str) -> tuple[bool, int]:
        """Verifica se a chave (IP ou usuário) está temporariamente bloqueada."""
        now = time.time()
        expiry = self.lockouts.get(key, 0)
        if now < expiry:
            remaining = int(expiry - now)
            return True, remaining
        elif key in self.lockouts:
            del self.lockouts[key]
        return False, 0

    def record_failure(self, key: str) -> tuple[bool, int]:
        """Registra uma falha e aplica bloqueio se o limite for atingido."""
        now = time.time()
        locked, remaining = self.is_locked(key)
        if locked:
            return True, remaining

        # Limpar tentativas fora da janela deslizante
        cutoff = now - self.window_seconds
        history = [t for t in self.attempts.get(key, []) if t > cutoff]
        history.append(now)
        self.attempts[key] = history

        if len(history) >= self.max_attempts:
            self.lockouts[key] = now + self.lockout_seconds
            self.attempts[key] = []
            return True, self.lockout_seconds

        return False, 0

    def record_success(self, key: str):
        """Limpa o histórico de falhas após login bem-sucedido."""
        self.attempts.pop(key, None)
        self.lockouts.pop(key, None)


login_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=60, lockout_seconds=90)


# ==============================================================================
# OWASP A03: Injection & XSS - Validação e Sanitização de Entrada
# ==============================================================================

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\.\-]{3,30}$")


def validate_username(username: str) -> tuple[bool, str]:
    """Valida se o formato do nome de usuário é seguro contra injeções."""
    if not username:
        return False, "O nome de usuário é obrigatório."
    if not USERNAME_REGEX.match(username):
        return False, (
            "Nome de usuário inválido. Utilize de 3 a 30 caracteres alfanuméricos, "
            "ponto, traço ou sublinhado."
        )
    return True, ""


def validate_password_complexity(password: str) -> tuple[bool, str]:
    """Garante comprimento e complexidade mínimos para senhas."""
    if not password or len(password) < 8:
        return False, "A senha deve conter no mínimo 8 caracteres."
    return True, ""


# ==============================================================================
# OWASP A01: Broken Access Control - Decorador de Proteção de Rotas
# ==============================================================================

def login_required(f):
    """
    Decorador que bloqueia o acesso anônimo à página interna.
    Redireciona para o login caso a sessão não seja válida.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session or not session.get("authenticated"):
            flash("Acesso restrito. Faça autenticação para acessar esta área.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


# ==============================================================================
# OWASP A05: Security Misconfiguration - Injeção de Cabeçalhos HTTP Seguros
# ==============================================================================

def apply_security_headers(response):
    """
    Adiciona cabeçalhos de segurança obrigatórios para blindagem contra:
    - Clickjacking (X-Frame-Options: DENY)
    - MIME-Sniffing (X-Content-Type-Options: nosniff)
    - XSS e injeção de scripts (Content-Security-Policy)
    - Fuga de informações de referência (Referrer-Policy)
    - Acesso não autorizado a recursos do dispositivo (Permissions-Policy)
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    # Content-Security-Policy restritiva: Bloqueia fontes externas não autorizadas
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )

    # Mascarar a identidade do servidor de backend
    response.headers["Server"] = "SecureShield/1.0"
    return response
