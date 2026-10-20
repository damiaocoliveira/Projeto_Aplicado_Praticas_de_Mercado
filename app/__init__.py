"""
Fábrica de Aplicação Flask (Application Factory).
Configura a aplicação com princípios de Secure by Design e Secure by Default.
"""

import os
import secrets
from datetime import timedelta
from flask import Flask, render_template
from app.security import apply_security_headers
from app.auth import auth_bp
from app.routes import main_bp


def create_app(test_config=None) -> Flask:
    """Cria e configura a instância da aplicação Flask com blindagem de segurança."""
    app = Flask(__name__, instance_relative_config=True)

    # Configurações de Segurança da Sessão (Secure by Default)
    # Se não houver SECRET_KEY configurada, gera uma chave criptográfica efêmera de 256 bits
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        SESSION_COOKIE_HTTPONLY=True,       # Impede roubo de sessão via JavaScript (XSS)
        SESSION_COOKIE_SAMESITE="Lax",      # Protege contra ataques de CSRF
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",  # Apenas HTTPS em produção
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=45),                   # Expiração temporal da sessão
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # Limita payload a 1MB (Prevenção de DoS em requisições)
        TEMPLATES_AUTO_RELOAD=True,          # Sempre recarrega templates modificados sem cache antigo
    )

    if test_config:
        app.config.update(test_config)

    # Injeção global de cabeçalhos de segurança em todas as respostas HTTP
    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)

    # Tratadores genéricos de erro (OWASP A05: Prevenção de vazamento de stacktrace)
    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html",
            code=400,
            title="Requisição Inválida",
            message="Os dados fornecidos não atendem aos critérios de validação."
        ), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "error.html",
            code=403,
            title="Acesso Negado",
            message="Você não possui permissão para acessar o recurso solicitado."
        ), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "error.html",
            code=404,
            title="Recurso Não Encontrado",
            message="O endpoint ou página requisitada não existe."
        ), 404

    @app.errorhandler(429)
    def too_many_requests(error):
        return render_template(
            "error.html",
            code=429,
            title="Limite de Requisições Excedido",
            message="Muitas tentativas detectadas. Aguarde antes de tentar novamente."
        ), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template(
            "error.html",
            code=500,
            title="Erro Interno do Servidor",
            message="Ocorreu um erro no processamento. Nossa equipe de segurança foi notificada."
        ), 500

    # Registro de Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    return app
