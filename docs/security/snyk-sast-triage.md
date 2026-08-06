# Triagem Snyk Code (SAST) — flext-sh/flext-auth

Gerado do scan Snyk da org Datacosmos (dump 2026-08-06).

**20 achados** — critical 0, high 0, medium 0, low 20

| categoria | achados |
|---|---|
| Use of Hardcoded Credentials | 11 |
| Use of Hardcoded Passwords | 8 |
| Hardcoded Non-Cryptographic Secret | 1 |

## Achados

Coluna **Decisão**: `corrigir` / `falso-positivo` / `risco-aceito`.

| # | sev | categoria | arquivo | linha | CWE | Decisão |
|---|---|---|---|---|---|---|
| 1 | low | Use of Hardcoded Credentials | `examples/basic_usage_flows.py` | 131 | - | |
| 2 | low | Use of Hardcoded Credentials | `examples/comprehensive_demo_03.py` | 27 | - | |
| 3 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_03.py` | 84 | - | |
| 4 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_03.py` | 98 | - | |
| 5 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_03.py` | 108 | - | |
| 6 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_04.py` | 19 | - | |
| 7 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_04.py` | 33 | - | |
| 8 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_04.py` | 53 | - | |
| 9 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_04.py` | 84 | - | |
| 10 | low | Use of Hardcoded Credentials | `tests/unit/api_cases/case_04.py` | 114 | - | |
| 11 | low | Hardcoded Non-Cryptographic Secret | `tests/unit/api_cases/case_05.py` | 111 | - | |
| 12 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/case_10.py` | 41 | - | |
| 13 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/case_10.py` | 43 | - | |
| 14 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/case_10.py` | 69 | - | |
| 15 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/case_10.py` | 75 | - | |
| 16 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/case_10.py` | 81 | - | |
| 17 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/support.py` | 20 | - | |
| 18 | low | Use of Hardcoded Passwords | `tests/unit/api_cases/support.py` | 30 | - | |
| 19 | low | Use of Hardcoded Passwords | `tests/unit/test_api.py` | 145 | - | |
| 20 | low | Use of Hardcoded Credentials | `tests/unit/test_token_real_flows.py` | 53 | - | |

## Como triar

1. Abrir `arquivo:linha` e seguir o fluxo de dados até o sink.
2. Classificar: **corrigir** (entrada externa alcança o sink sem sanitização), **falso-positivo** (credencial de fixture, path de constante — registrar em `.snyk` com justificativa), **risco-aceito** (com prazo de revisão).

Dados brutos: `~/snyk-violations/sast/flext-sh__flext-auth.sast.json`

