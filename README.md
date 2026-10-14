# 🛡️ SecureShield - Projeto Aplicado: Práticas de Mercado

> **Disciplina:** Projeto Aplicado: Práticas de Mercado  
> **Foco:** Segurança da Informação & DevSecOps  
> **Abordagem:** *Secure by Design* e *Secure by Default*  
> **Ambiente de Desenvolvimento (IDE):** Google Antigravity  

---

## 📌 1. Visão Geral do Projeto

Este projeto consiste em um protótipo de software web desenvolvido com foco rigoroso em **Segurança da Informação**, simulando um ambiente de desenvolvimento de mercado com automação de ponta a ponta. 

A solução integra dois eixos fundamentais interligados por uma esteira de automação (**CI**):
- **Eixo 2 (Repositório Seguro & DevSecOps):** Versionamento no GitHub com boas práticas de segurança, arquivo `.gitignore` restritivo para prevenção de vazamento de segredos, proteção de branch (`Branch Protection`), monitoramento automatizado de vulnerabilidades (`Dependabot`) e autenticação via chaves criptográficas (SSH/PAT).
- **Eixo 3 (Desenvolvimento Web Seguro & OWASP Top 10):** Aplicação web com tela de **Login**, **Página Interna protegida** e **Logout funcional**, com tratamento criptográfico de credenciais (zero senhas em texto puro) e mitigação ativa de **5 vulnerabilidades do OWASP Top 10**.
- **Automação (CI - GitHub Actions):** Pipeline automatizada acionada em cada *push* ou *pull request*, executando testes unitários, análise estática de segurança de código (**SAST** com Bandit), escaneamento de segredos (**Secret Scanning** com Gitleaks) e linting de qualidade (**Flake8**).

---

## 🏗️ 2. Arquitetura da Solução e Estrutura de Arquivos

O projeto adota arquitetura modular com separação clara de responsabilidades:

```text
PROJETO 2/
├── .github/
│   ├── dependabot.yml           # Monitoramento automático de vulnerabilidades em dependências
│   └── workflows/
│       └── ci.yml               # Pipeline de CI (Pytest + Bandit SAST + Flake8 + Gitleaks)
├── app/
│   ├── __init__.py              # Application Factory, headers globais e error handlers genéricos
│   ├── auth.py                  # Rotas de Login/Logout, proteção anti-brute force e anti-enumeração
│   ├── routes.py                # Página interna protegida (/dashboard) com decorador @login_required
│   ├── security.py              # Mecanismos criptográficos (PBKDF2), rate limiter e headers de segurança
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css        # Interface moderna, responsiva e alinhada ao CSP (sem CDNs externas)
│   │   └── js/
│   │       └── main.js          # Scripts de frontend seguros sem inline-scripts ou eval
│   └── templates/
│       ├── base.html            # Template base com CSP, viewport e feedback de mensagens
│       ├── login.html           # Tela de Login com campos seguros e indicadores de proteção
│       ├── dashboard.html       # Página Interna restrita com dados da sessão e botão de Logout
│       └── error.html           # Tratamento seguro de páginas de erro (400, 403, 404, 429, 500)
├── tests/
│   ├── test_auth.py             # Testes de autenticação, logout, controle de acesso e rate limit
│   └── test_security.py         # Testes de cabeçalhos HTTP, hashing PBKDF2 e sanitização
├── .env.example                 # Exemplo seguro de variáveis de ambiente (sem segredos reais)
├── .gitignore                   # Regras rigorosas para evitar vazamento de credenciais e .env
├── pytest.ini                   # Configuração de descoberta de testes e pythonpath
├── requirements.txt             # Dependências de produção (Flask, Werkzeug)
├── requirements-dev.txt         # Dependências de CI/Dev (Pytest, Bandit, Flake8, pip-audit)
├── run.py                       # Ponto de entrada para execução local da aplicação
└── README.md                    # Relatório técnico completo de entrega
```

---

## 🔒 3. Comprovação Técnica das 5 Mitigações do OWASP Top 10

Conforme as diretrizes da avaliação, a aplicação mitiga ativamente **5 (cinco) categorias críticas** do catálogo oficial da OWASP:

| Categoria OWASP | Vetor de Ameaça Mapeado | Mitigação Implementada no Código | Arquivo(s) e Linha(s) de Referência |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Acesso indevido de usuários anônimos a páginas restritas e sequestro de sessão pós-logout. | Implementação do decorador `@login_required` para interceptar e bloquear requisições não autenticadas ao `/dashboard`, redirecionando para `/login`. Invalidação completa da sessão (`session.clear()`) no `/logout`. | `app/security.py` (função `login_required`)<br>`app/routes.py` (rota `/dashboard`)<br>`app/auth.py` (rota `/logout`) |
| **A02: Cryptographic Failures** | Armazenamento de senhas em texto puro ou uso de algoritmos criptográficos obsoletos (MD5/SHA1). | Senhas nunca são salvas ou comparadas em texto puro. Utilização de **PBKDF2 com HMAC-SHA256 e salt criptográfico** (600.000 iterações via Werkzeug Security). Cookies de sessão assinados com segredo de 256 bits, configurados com flags `HttpOnly=True` e `SameSite=Lax`. | `app/security.py` (`hash_password`, `verify_password`, `USERS_DB`)<br>`app/__init__.py` (flags de sessão) |
| **A03: Injection & XSS** | Injeção de scripts maliciosos (Cross-Site Scripting) e manipulação indevida de parâmetros. | Sanitização e validação por expressão regular no nome de usuário (`validate_username`), mecanismo nativo de auto-escape do Jinja2 e injeção do cabeçalho restritivo **Content-Security-Policy (CSP)** bloqueando scripts e fontes não autorizadas. | `app/security.py` (`validate_username`, `apply_security_headers`)<br>`app/templates/base.html` |
| **A05: Security Misconfiguration** | Clickjacking, MIME-sniffing, exposição de versão do servidor e vazamento de stack traces em erros. | Injeção global de cabeçalhos de defesa HTTP (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`). Mascaramento de cabeçalho `Server` e páginas genéricas de erro (400, 403, 404, 429, 500) sem traces internos. | `app/security.py` (`apply_security_headers`)<br>`app/__init__.py` (`@app.errorhandler`)<br>`app/templates/error.html` |
| **A07: Identification and Authentication Failures** | Ataques de força bruta contra o login, enumeração de usuários válidos e fixação de sessão. | Implementação de **Rate Limiting** em memória (`InMemoryRateLimiter`) que bloqueia o IP após 5 tentativas consecutivas de falha. Mensagens de erro padronizadas e genéricas (*"Credenciais inválidas"*) impedindo enumeração. Limpeza e regeneração de sessão no login contra fixação de sessão. | `app/security.py` (`InMemoryRateLimiter`)<br>`app/auth.py` (lógica de validação e rate limit no `/login`) |

---

## 🚀 4. Como Executar o Projeto Localmente

### Pré-requisitos
- **Python 3.10 ou superior** instalado na máquina.
- Gerenciador de pacotes **pip**.

### Passo a Passo de Execução

1. **Acessar a pasta raiz do projeto:**
   ```bash
   cd "c:\Users\ssrbe\Downloads\PROJETO 2"
   ```

2. **Criar e ativar o ambiente virtual (venv):**
   - No Windows (PowerShell):
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - No Linux/macOS:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Instalar as dependências do projeto:**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Executar a aplicação:**
   ```bash
   python run.py
   ```
   A aplicação será iniciada no endereço: **`http://127.0.0.1:5000`**

5. **Acessar e Testar pelo Navegador:**
   - Acesse: `http://127.0.0.1:5000/login`
   - **Credenciais para Demonstração e Avaliação:**
     - **Perfil Administrador:**
       - Usuário: `admin`
       - Senha: `AdminSecure@2026`
     - **Perfil Auditor:**
       - Usuário: `auditor`
       - Senha: `AuditPass@2026`

---

## 🧪 5. Execução dos Testes Automatizados e Auditoria de Segurança Local

O projeto conta com suíte automatizada de testes e ferramentas de análise estática de segurança (SAST):

### Executar Testes Unitários e Funcionais (Pytest)
Valida todas as regras de autenticação, persistência de sessão, decoradores de proteção e controle de força bruta:
```bash
pytest -v tests/
```
*Resultado esperado: 13 testes executados com 100% de aprovação (PASS).*

### Executar Análise Estática de Segurança - SAST (Bandit)
Realiza a varredura completa do código-fonte em busca de falhas de segurança e más práticas de codificação:
```bash
bandit -r app/ -ll --exclude .venv,tests
```
*Resultado esperado: 0 vulnerabilidades identificadas (Total issues: 0).*

### Executar Validação de Estilo e Qualidade (Flake8)
```bash
flake8 app/ tests/ --count --max-line-length=120 --statistics
```
*Resultado esperado: 0 erros de conformidade (Exit code 0).*

---

## 🔄 6. Integração Contínua (CI com GitHub Actions)

O arquivo `.github/workflows/ci.yml` automatiza a esteira de validação a cada alteração no repositório:

### Gatilhos da Pipeline
- **Push** para as branches `main` ou `master`.
- Abertura ou atualização de **Pull Request (PR)** direcionado à branch principal.

### Etapas da Pipeline
1. **Checkout do Repositório:** Clona o código com histórico completo (`fetch-depth: 0`).
2. **Secret Scanning (Gitleaks):** Analisa todos os commits para garantir que nenhuma chave privada, token ou senha foi versionada inadvertidamente.
3. **Setup do Python:** Inicializa o runtime Python oficial no runner Ubuntu.
4. **Instalação das Dependências:** Restaura os pacotes descritos em `requirements-dev.txt`.
5. **Auditoria SAST (Bandit):** Verifica a integridade e padrões de segurança do código-fonte.
6. **Linting (Flake8):** Garante a formatação e ausência de problemas sintáticos.
7. **Testes Automatizados (Pytest):** Executa a suíte de testes completa, exigindo aprovação integral (`status: pass`) para aprovação do fluxo.

---

## 📦 7. Guia de Configuração Segura do Repositório (Eixo 2)

Para cumprir integralmente os requisitos do **Eixo 2**, siga as instruções abaixo na plataforma GitHub:

### 7.1. Criação do Repositório Público
1. Acesse o [GitHub](https://github.com) e crie um novo repositório com visibilidade **Public** (Público).
2. Não marque a opção de adicionar `.gitignore` ou `README` pelo site (pois já foram criados localmente com rigor técnico).

### 7.2. Configuração de Acesso Seguro (SSH ou PAT)
- **Opção recomendada (Chave SSH):**
  1. Gere seu par de chaves no computador:
     ```bash
     ssh-keygen -t ed25519 -C "seu_email@dominio.com"
     ```
  2. Adicione a chave pública (`id_ed25519.pub`) nas configurações da sua conta do GitHub em:  
     `Settings` > `SSH and GPG keys` > `New SSH key`.
- **Autenticação em Duas Etapas (2FA):**
  Ative a verificação em duas etapas em `Settings` > `Password and authentication` > `Two-factor authentication`.

### 7.3. Habilitação de Alertas do Dependabot
1. No repositório do GitHub, clique na aba **Settings**.
2. No menu lateral, acesse **Code security and analysis**.
3. Ative as opções:
   - **Dependabot alerts** (Alertas de vulnerabilidades em bibliotecas)
   - **Dependabot security updates** (Criação automática de PRs para correção)
   - O arquivo `.github/dependabot.yml` já presente no código sincronizará as checagens semanais.

### 7.4. Configuração de Proteção de Branch (Branch Protection)
1. No repositório, acesse **Settings** > **Branches**.
2. Clique em **Add branch protection rule** (ou **Add rule**).
3. No campo *Branch name pattern*, digite `main` (ou `master`).
4. Marque as seguintes caixas:
   - [x] **Require a pull request before merging** (Impede o push direto na branch principal).
   - [x] **Require status checks to pass before merging** (Exige que a pipeline do GitHub Actions encerre com sucesso).
     - Selecione o check: `Build, SAST & Test`.
5. Salve as alterações clicando em **Save changes**.

---

## 🤖 8. Codificação Assistida por Inteligência Artificial (Google Antigravity)

Conforme exigido pelo documento da disciplina, este protótipo foi inteiramente concebido, estruturado, auditado e refatorado através de **Codificação Assistida por IA** utilizando o **Google Antigravity**:
- **Design de Arquitetura Segura:** Formulação da estratégia *Secure by Design*, seleção dos algoritmos de hashing recomendados pela OWASP e blindagem de cabeçalhos HTTP.
- **Implementação e Refatoração:** Geração assistida de código defensivo, validação rigorosa de formatos e criação dos templates HTML/CSS sem dependências externas suscetíveis a ataques à cadeia de suprimentos (*Supply Chain Attacks*).
- **Auditoria de Código e Cobertura de Testes:** Elaboração automatizada dos testes unitários em `pytest` e varredura estática de conformidade com `bandit` e `flake8`.

---

## ✅ 9. Checklist Final de Entrega

- [x] **Repositório Público no GitHub:** Repositório criado e configurado (Eixo 2).
- [x] **Acesso Seguro:** Operações via SSH/PAT e 2FA recomendado (Eixo 2).
- [x] **Prevenção de Vazamento:** Arquivo `.gitignore` configurado; zero senhas ou arquivos `.env` commitados (Eixo 2).
- [x] **Monitoramento Ativo:** Dependabot configurado via `.github/dependabot.yml` (Eixo 2).
- [x] **Proteção de Branch:** Regras de Branch Protection para a branch principal descritas e prontas para ativação (Eixo 2).
- [x] **Estrutura Mínima Completa:** Tela de Login, Página Interna restrita e Logout funcional (Eixo 3).
- [x] **Tratamento de Credenciais:** Hashes seguros PBKDF2-HMAC-SHA256 com salt; zero senhas em texto puro (Eixo 3).
- [x] **Mitigação de 5 Vulnerabilidades OWASP:** A01, A02, A03, A05 e A07 documentadas e implementadas no código (Eixo 3).
- [x] **Execução Local Funcional:** Aplicação roda perfeitamente via `python run.py` (Eixo 3).
- [x] **Pipeline de CI (GitHub Actions):** Workflow configurado com Testes, SAST (Bandit), Linting (Flake8) e Secret Scanning (Gitleaks) com encerramento em status `PASS` (CI).
- [x] **Relatório Técnico Detalhado:** README.md com instruções completas e comprovação dos critérios de avaliação.
