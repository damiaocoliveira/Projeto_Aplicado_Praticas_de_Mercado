"""
Ponto de Entrada da Aplicação (Local Server).
Inicia o servidor web Flask para testes e avaliação local.
"""

import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=False por padrão (Secure by Default) para não expor o debugger do Werkzeug em produção
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

    print("=" * 70)
    print("🛡️  PROJETO APLICADO: PRÁTICAS DE MERCADO - SECURE BY DESIGN")
    print("=" * 70)
    print(f"🚀 Servidor rodando em: http://127.0.0.1:{port}")
    print("🔒 Credenciais de teste simuladas (Hashes seguros PBKDF2 em memória):")
    print("   👤 Usuário: admin    | Senha: AdminSecure@2026")
    print("   👤 Usuário: auditor  | Senha: AuditPass@2026")
    print("=" * 70)

    app.run(host="127.0.0.1", port=port, debug=debug_mode)
