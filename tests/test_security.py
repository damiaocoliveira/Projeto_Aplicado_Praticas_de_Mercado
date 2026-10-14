"""
Testes de Cabeçalhos HTTP, Criptografia e Blindagem de Segurança (OWASP).
Validação de:
- OWASP A02: Cryptographic Failures (PBKDF2 Hashing)
- OWASP A03: Injection & XSS (CSP, Validação de inputs)
- OWASP A05: Security Misconfiguration (Cabeçalhos HTTP seguros e tratamento de erro)
"""

import pytest
from app import create_app
from app.security import (
    hash_password,
    verify_password,
    validate_username,
    validate_password_complexity,
    USERS_DB
)


@pytest.fixture
def app():
    return create_app({"TESTING": True, "SECRET_KEY": "security-test-key"})


@pytest.fixture
def client(app):
    return app.test_client()


def test_security_headers_present_on_all_responses(client):
    """
    OWASP A05 (Security Misconfiguration):
    Garante a presença de todos os cabeçalhos de segurança obrigatórios.
    """
    response = client.get("/login")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
    assert response.headers.get("Server") == "SecureShield/1.0"


def test_password_hashing_pbkdf2_validation():
    """
    OWASP A02 (Cryptographic Failures):
    Garante que senhas utilizem hash PBKDF2 com SHA-256 e salt, sem texto claro.
    """
    plain = "SuperSecretPass2026!"
    hashed = hash_password(plain)

    # Verifica formato do hash seguro
    assert hashed.startswith("pbkdf2:sha256:")
    assert plain not in hashed

    # Validação do hash
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_no_plaintext_passwords_in_simulated_database():
    """
    OWASP A02:
    Assegura que nenhuma conta possua senhas em texto puro no banco de dados.
    """
    for username, user_data in USERS_DB.items():
        assert "password" not in user_data
        assert "password_hash" in user_data
        assert user_data["password_hash"].startswith("pbkdf2:sha256:")


def test_username_validation_prevents_injections():
    """
    OWASP A03 (Injection & XSS):
    Testa se o validador de input bloqueia payloads maliciosos.
    """
    valid_ok, _ = validate_username("admin_valid")
    assert valid_ok is True

    # Bloqueio de injeções clássicas e XSS
    bad_inputs = [
        "<script>alert(1)</script>",
        "admin' OR '1'='1",
        "../../etc/passwd",
        "ab",  # Muito curto
        "a" * 35,  # Muito longo
        "admin user with spaces",
        "admin;DROP TABLE users;--"
    ]
    for bad in bad_inputs:
        is_valid, _ = validate_username(bad)
        assert is_valid is False, f"Falha: {bad} não deveria ser considerado válido"


def test_password_complexity_validation():
    """Valida requisitos de tamanho mínimo da senha."""
    is_valid, _ = validate_password_complexity("1234567")
    assert is_valid is False
    is_valid, _ = validate_password_complexity("12345678")
    assert is_valid is True


def test_404_error_handler_masks_internals(client):
    """
    OWASP A05:
    Página 404 customizada não expõe traces técnicos do Flask/Python.
    """
    response = client.get("/rota-inexistente-de-teste")
    assert response.status_code == 404
    assert b"Recurso N\xc3\xa3o Encontrado" in response.data or b"Recurso N" in response.data
    assert b"Traceback" not in response.data
