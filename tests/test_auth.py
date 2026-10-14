"""
Testes Automatizados de Autenticação e Controle de Acesso (Eixo 3).
Validação de:
- OWASP A01: Broken Access Control
- OWASP A02: Cryptographic Failures
- OWASP A07: Identification and Authentication Failures
"""

import pytest
from app import create_app
from app.security import login_limiter


@pytest.fixture
def app():
    """Cria e configura uma instância de teste da aplicação."""
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-crypto-secret-key-for-unit-testing-only",
        "WTF_CSRF_ENABLED": False,
    })
    yield application


@pytest.fixture
def client(app):
    """Cliente de testes HTTP."""
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_limiter():
    """Garante isolamento dos testes limpando o rate limiter."""
    login_limiter.attempts.clear()
    login_limiter.lockouts.clear()
    yield


def test_login_page_renders(client):
    """Verifica se a tela de login renderiza com status HTTP 200."""
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Portal de Acesso Seguro" in response.data
    assert b"Identificador / Usu" in response.data


def test_unauthenticated_dashboard_redirects_to_login(client):
    """
    OWASP A01 (Broken Access Control):
    Garante que usuário anônimo NÃO consiga acessar a página interna (/dashboard).
    """
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_success(client):
    """
    Garante que credenciais corretas autenticam e redirecionam para o dashboard.
    """
    response = client.post("/login", data={
        "username": "admin",
        "password": "AdminSecure@2026"
    }, follow_redirects=False)

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]

    # Seguindo o redirecionamento para a página interna
    dash_response = client.get("/dashboard")
    assert dash_response.status_code == 200
    assert b"Painel de Controle Seguro" in dash_response.data
    assert b"Administrador / SecOps" in dash_response.data


def test_login_invalid_password_returns_401(client):
    """
    OWASP A07:
    Senha incorreta retorna erro genérico 401 sem revelar detalhes.
    """
    response = client.post("/login", data={
        "username": "admin",
        "password": "WrongPassword123!"
    })
    assert response.status_code == 401
    assert b"Credenciais" in response.data


def test_login_invalid_user_returns_401_generic(client):
    """
    OWASP A07 (Anti-Enumeration):
    Usuário inexistente recebe mensagem IDÊNTICA à de senha incorreta.
    """
    response = client.post("/login", data={
        "username": "non_existent_user",
        "password": "SomePassword123!"
    })
    assert response.status_code == 401
    assert b"Credenciais" in response.data


def test_logout_invalidates_session(client):
    """
    OWASP A01:
    O logout deve desautenticar o usuário e impedi-lo de acessar o dashboard.
    """
    # 1. Faz login com sucesso
    client.post("/login", data={
        "username": "admin",
        "password": "AdminSecure@2026"
    })

    # 2. Executa o logout
    logout_res = client.get("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"Sess" in logout_res.data

    # 3. Tenta acessar novamente o dashboard restrito
    dash_again = client.get("/dashboard")
    assert dash_again.status_code == 302
    assert "/login" in dash_again.headers["Location"]


def test_rate_limiting_locks_out_after_5_attempts(client):
    """
    OWASP A07:
    Proteção contra Força Bruta: Bloqueia com HTTP 429 após 5 tentativas falhas.
    """
    for _ in range(5):
        client.post("/login", data={
            "username": "admin",
            "password": "InvalidPassword"
        })

    # A 6ª tentativa deve ser bloqueada imediatamente pelo rate limiter
    response = client.post("/login", data={
        "username": "admin",
        "password": "AdminSecure@2026"
    })
    assert response.status_code == 429
    assert b"Muitas tentativas" in response.data or b"Limite de tentativas" in response.data
