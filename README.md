# 🚀 ComplyScan Pro

**Turnkey GDPR/SOC2/CCPA Compliance SaaS — Multi-Tenant, Stripe Billing, 8 Languages**

Paste any URL → scan for compliance violations → get a score + PDF report → charge customers $99/mo.

## 📦 Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Crawler    │────▶│  AI Analyst  │────▶│   Backend   │
│  (port 8000)│     │  (port 8001) │     │  (port 8002)│
│  Playwright │     │  Claude AI   │     │  FastAPI    │
└─────────────┘     └──────────────┘     └─────────────┘
                                               │
                                        ┌──────┴──────┐
                                        │  Dashboard  │
                                        │  + Admin    │
                                        │  + Stripe   │
                                        └─────────────┘
```

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/ilo97/ComplyScan.git
cd ComplyScan

# 2. Configure
cp .env.template .env
# Edit .env with your API keys (Stripe, Anthropic)

# 3. Launch
docker-compose up -d

# 4. Open
open http://localhost:8002
```

## 🧩 Modules

| Module | Tech | Port | Description |
|--------|------|------|-------------|
| 🕷️ **Crawler** | Playwright + FastAPI | 8000 | Scans cookies, headers, forms, SSL/TLS, privacy policies |
| 🤖 **AI Analyst** | Claude API + FastAPI | 8001 | GDPR (8 articles) + SOC2 + CCPA analysis, scoring 0-100 |
| ⚙️ **Backend** | FastAPI + SQLite/PostgreSQL | 8002 | Multi-tenant, Stripe billing, admin panel, PDF reports |

## 💳 Built-in Pricing

| Plan | Price | Features |
|------|-------|----------|
| 🟢 Starter | $99/mo | 1 domain, weekly scan, PDF reports |
| 🟡 Growth | $299/mo | 5 domains, daily scan, priority support |
| 🔴 Enterprise | $999/mo | Unlimited, API access, white-label |

## 🌍 Languages

🇬🇧 English (default) · 🇹🇷 Türkçe · 🇩🇪 Deutsch · 🇫🇷 Français · 🇪🇸 Español · 🇮🇹 Italiano · 🇳🇱 Nederlands · 🇵🇹 Português

## 🔒 Compliance Standards

- **GDPR** — Articles 5, 7, 12-14, 15-22, 27, 28, 33-34, 37
- **SOC2** — Security, Availability, Processing Integrity, Confidentiality, Privacy
- **CCPA** — Right to know, delete, opt-out, Do Not Sell

## 🏗️ Project Structure

```
complyscan-pro/
├── backend/          # FastAPI + multi-tenant + Stripe
│   ├── app/          # Python source
│   ├── static/       # Frontend assets
│   └── Dockerfile
├── crawler/          # Playwright crawler engine
├── analyst/          # Claude AI analysis engine
├── docker-compose.yml
├── .env.template
└── README.md
```

---

Built by a 4-person AI team. Questions? → [GitHub Issues](https://github.com/ilo97/ComplyScan/issues)