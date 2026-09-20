# 🏦 NeoBank ARIA — AI Security Workshop

**ARIA** (Automated Response & Inquiry Assistant) is NeoBank's intentionally vulnerable AI banking assistant, built for the Gen Academy AI security workshop. Participants interact with ARIA to explore common AI-agent security weaknesses through hands-on testing, including prompt injection, information disclosure, unsafe tool use, and multi-turn attacks.

The application uses a Streamlit interface, an OpenAI-powered LangChain agent, a local SQLite database, and a simple Python knowledge base. All NeoBank customers, accounts, balances, and transactions in this project are fictional.

## Quick Start

### 1. Prerequisites

- Python 3.10 or newer
- pip
- An [OpenAI API key](https://platform.openai.com/api-keys)

### 2. Create and activate a virtual environment

#### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Run the app

```bash
python -m streamlit run app.py
```

Streamlit will normally open the application automatically. Otherwise, open:

```text
http://localhost:8501
```

### 5. Enter your API key

Enter your own OpenAI API key in the sidebar. The app validates the key before allowing access to the chatbot.

### 6. Sign in

Use the fictional NeoBank customer account provided for the workshop.

| Name | User ID | Tier |
|---|---|---|
| Alex Mercer | USR-0042 | Standard |
| Morgan Hayes | USR-STAFF-01 | Staff |

Sign in as **Morgan Hayes** to exercise the staff path: staff can read internal-only knowledge base articles and look up any customer's account (elevated access). Signed in as a Standard customer, both are blocked.

Other fictional accounts exist in the database and form part of the security exercise.

---

## Project Structure

```text
week6-neobank-aria-agent/
├── app.py
├── agent.py
├── guardrails.py
├── database.py
├── knowledge_base.py
├── seed_data.py
├── neobank.db
├── requirements.txt
├── architecture.html
├── security_guide.html
├── .gitignore
└── README.md
```

### Main files

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI, API-key validation, login flow, chat interface, navigation, and workshop challenges |
| `agent.py` | ARIA agent built with LangChain and OpenAI tools |
| `guardrails.py` | LLM Guard input/output scanner stacks (prompt-injection, toxicity, PII, banned topics, sensitive-data, relevance) |
| `database.py` | SQLite connection, initialization, authentication, and query helpers |
| `knowledge_base.py` | NeoBank policy and knowledge-base content |
| `seed_data.py` | Fictional customer, account, and transaction seed data |
| `neobank.db` | SQLite database used by the workshop |
| `architecture.html` | In-app architecture reference |
| `security_guide.html` | In-app AI security guide |
| `requirements.txt` | Python dependencies |

---

## Requirements

ARIA uses:

```text
streamlit>=1.38.0
langchain>=0.3.0
langchain-openai>=0.3.0
langchain-core>=0.3.0
python-dotenv>=1.0.0
llm-guard>=0.3.15
```

Install the repository's current `requirements.txt` before running the app.

> **Note:** `llm-guard` pulls in `torch`, `transformers`, and `presidio`. The
> first run downloads the guardrail models (several hundred MB) and may take a
> few minutes; subsequent runs load them from the local cache.

---

## Architecture

- **LLM:** OpenAI `gpt-4o-mini`
- **Agent framework:** LangChain
- **Database:** SQLite
- **Knowledge base:** Python dictionary
- **UI:** Streamlit
- **Authentication:** Fictional NeoBank customer lookup
- **API access:** User-supplied OpenAI API key
- **Guardrails:** LLM Guard input/output scanner stack (see below)

ARIA began as an intentionally **unguarded security-testing target**, to demonstrate why model instructions alone are not a sufficient security boundary. It now ships with a modular guardrail layer so participants can compare the guarded and unguarded behaviours.

### Guardrail layer

`guardrails.py` assembles two [LLM Guard](https://llm-guard.com/) scanner stacks, wired into the chat flow in `app.py`:

- **Input scanners** (run on the user's message before it reaches the agent): prompt-injection, toxicity, PII anonymisation, banned topics. If any scanner fails, the request is **blocked** and the agent is never called. The PII scanner (`Anonymize`) redacts personal data in place rather than blocking, so the model only ever sees a sanitised prompt. The prompt-injection scanner uses the `v1` detection model on purpose: the newer `v2` model hard-flags ordinary second-person banking commands ("can you provide my account information?") as injection with maximum confidence, which no threshold can rescue, whereas `v1` clears those while still catching classic injections.
- **Output scanners** (run on the agent's answer before it is shown): toxicity, sensitive-data leakage, relevance. If any scanner fails, the answer is **suppressed**. The sensitive-data scanner is scoped to high-severity secrets that must never appear in any answer (card numbers, SSNs, bank/IBAN numbers, crypto wallets) via `SENSITIVE_OUTPUT_ENTITIES` in `guardrails.py`. It deliberately does not flag ordinary contact PII (name, email, phone), because showing an authenticated customer their own details is the assistant's core job and who may see an account is enforced at the tool/access-control layer, not here.

Banned topics default to violence/illegal activity, self-harm/hate, investment/crypto advice, and politics/religion (configurable via `BANNED_TOPICS` in `guardrails.py`).

### Access controls

Authorisation is enforced at the tool/data layer in `agent.py` (bound to the authenticated identity, so it holds even if the model is manipulated):

- **Knowledge base:** articles listed in `INTERNAL_ONLY_TOPICS` (`knowledge_base.py`) are staff-only. For customers they are never returned and never referenced — a customer cannot even tell such an article exists (requesting one is answered identically to a non-existent topic, and internal topics are excluded from both the system prompt and the "available topics" list).
- **Account scope:** `query_account` only returns the signed-in user's own account. A non-staff user requesting another `user_id` is denied with no data disclosed. Staff (`tier = Staff`) have elevated access and may look up any account.

### Prompt spotlighting

`agent.py` delimits untrusted content so the model treats it as data, not instructions (defence in depth alongside the `PromptInjection` scanner):

- The customer's message is wrapped in `[untrusted_user_message ...]` tags, and tool results in `[untrusted_tool_output ...]` tags. The system prompt instructs ARIA to act on legitimate requests but refuse any instruction inside those tags that tries to change its rules, reveal the system prompt, or bypass access controls, and to never execute instructions embedded in tool output (indirect prompt injection).
- Each tag carries an unguessable per-request token, so an attacker cannot forge a closing tag to "break out" of the delimiters.

### System prompt hardening

The system prompt opens with a set of non-negotiable rules (defence in depth, not a hard boundary) targeting common jailbreak techniques: persona/role-play switches (DAN, "developer mode"), prompt-continuation and instruction-extraction, hypothetical/fictional framing, emotional-appeal ("grandma") exploits, and obfuscation/encoding. ARIA is also told to refuse briefly without revealing which rule applied or how to bypass it. The model is `gpt-4o-mini`, which is materially harder to jailbreak than the older `gpt-3.5-turbo`.

### Multi-turn (crescendo) defence

A crescendo attack spreads a jailbreak across several individually-innocuous turns that gradually steer the assistant past its rules. The per-message input scanners are stateless, so they cannot see this trajectory. ARIA layers three defences against it:

- **Prompt rule:** the non-negotiable rules tell ARIA to judge every request on its own merits, and that conversation history and its own earlier answers never expand what it may do. A reframed version of an already-declined request is declined again.
- **Trajectory judge:** `scan_conversation` (`guardrails.py`) sends the recent turns plus the current message to a cheap `gpt-4o-mini` monitor that decides whether the conversation is a deliberate escalation toward a prohibited goal. It runs only once there are at least two prior turns, and **fails open** (a judge outage never takes the assistant down). If it flags escalation, the turn is blocked before the agent is called.
- **Refusal ratchet:** consecutive blocked requests (any input scanner or the trajectory judge) increment a counter; a clean turn resets it. After `CRESCENDO_LOCK_THRESHOLD` (3) consecutive blocks the conversation is **locked**, the chat input is disabled, and the user must use **Clear Chat** to start a new session. This denies an attacker unlimited retries to probe for a working sequence.

---

## Workshop Challenges

The sidebar includes guided security challenges covering areas such as:

- Jailbreaking
- Obfuscation
- Sensitive data exposure
- Prompt injection
- Red teaming
- Multi-turn escalation
- PII extraction

Participants are expected to test ARIA within the scope of the fictional workshop environment.

---

## Important Security Notes

- Do not commit real API keys to the repository.
- Do not place secrets directly in `app.py`, `agent.py`, or other tracked files.
- Use only fictional workshop data.
- This project intentionally contains insecure behavior for educational testing.
- Do not use this implementation as a production banking assistant.

---

### API key is rejected

Confirm that the OpenAI API key:

- is complete,
- is still active,
- belongs to an OpenAI project/account with API access,
- and can reach OpenAI from the current network.

---

## Disclaimer

NeoBank, ARIA, all customer identities, accounts, balances, and transactions in this repository are fictional.

This project is intended solely for educational use, controlled AI-security testing, and red-team exercises.

---

*Gen Academy · AI Security Workshop*
