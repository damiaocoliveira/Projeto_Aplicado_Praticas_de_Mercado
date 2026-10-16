"""
Ponto de Entrada da Aplicacao (Local Server).
Inicia o servidor web Flask para testes e avaliacao local.
"""

import sys
import os

# Configura encoding UTF-8 seguro para terminais Windows (evita UnicodeEncodeError em codepages CP1252/OEM)
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=False por padrao (Secure by Default) para nao expor o debugger do Werkzeug em producao
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

    print("=" * 70)
    print("[SECURESHIELD] PROJETO APLICADO: PRATICAS DE MERCADO - SECURE BY DESIGN")
    print("=" * 70)
    print(f"[*] Servidor rodando em: http://127.0.0.1:{port}")
    print("[*] Credenciais de teste simuladas (Hashes seguros PBKDF2 em memoria):")
    print("    - Usuario: admin    | Senha: AdminSecure@2026")
    print("    - Usuario: auditor  | Senha: AuditPass@2026")
    print("=" * 70)

    app.run(host="127.0.0.1", port=port, debug=debug_mode)
