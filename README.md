# vulnhound
A bot that fetches the latest web vulnerabilities (CVEs, exploits, PoCs) and posts them to Discord

# Objetivo

Criar uma ferramenta que coleta vulnerabilidades recentes (CVEs, PoCs, exploits) e envia para um canal do Discord, com foco em bug bounty web.

Podemos dividir em objetivos principais e secundários:

# 🔹 Objetivos principais (MVP)

1. Coletar vulnerabilidades de fontes confiáveis
- CVE feeds (NVD, CVE Program).
- Exploit-DB (WebApps).
- PoC-in-GitHub (repositórios com CVEs recentes).
- Notícias relevantes sobre bugs web.

2. Filtrar pelo que interessa para bug bounty web
- Categorias web (RCE em frameworks, XSS, SQLi, WordPress, etc).
- Evitar ruído (CVE de driver de impressora, kernel, etc).
- Enviar alertas para o Discord
- Usar Webhook.
- Enviar título, descrição resumida, link para detalhes, data.

# 🔹 Objetivos secundários (versões futuras)
- Checar se existe template Nuclei para o CVE encontrado.
- Permitir registrar targets e rodar templates automaticamente.
- Manter histórico (ex: armazenar em SQLite ou JSON local).
- Painel web simples para ver alertas (se evoluir para SaaS).