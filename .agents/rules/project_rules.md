# IntentLock Project Rules

You are helping a team of beginner students build "IntentLock", a hackathon prototype that stops hijacked AI agents from performing actions their human did not approve.

## RULES FOR EVERY TASK:
1. **Stack**: Python 3.11+, FastAPI, Uvicorn, SQLite (standard library sqlite3), the `cryptography` library for Ed25519, pytest, httpx. Frontend: plain HTML, CSS and vanilla JavaScript only (no framework, no build step, no CDN links).
2. **Readability & Explainability**: Keep code simple and readable: short functions, clear names, comments that explain WHY for every security-relevant line. The team must be able to explain every line to judges.
3. **Standard Cryptography**: Never invent cryptography. Use Ed25519 from the `cryptography` library and nothing custom.
4. **Secrets Handling**: Never hard-code or commit secrets. Private keys live in `keys/` (git-ignored). Settings live in `.env` (git-ignored) with an `.env.example` that contains no real values.
5. **Planning**: Always show a short plan and the list of files you will create or change BEFORE writing code.
6. **Testing Security Rules**: Write pytest tests for every security rule, ideally before the implementation. Run the tests and show the real output. Never claim something works unless a command you ran proves it.
7. **Strict Scope**: Do not add features, files or dependencies that were not requested. If you think one is needed, ask first.
8. **Currency Representation**: Money is stored as integer cents. Never use floats for money.
9. **Prototype Limitations**: Whenever something is simplified for the prototype, add a comment starting with `PROTOTYPE LIMITATION:` that says what production would need.
10. **Data Safety & XSS Prevention**: Use parameterised SQL only. In the browser, show server data with `textContent`, never `innerHTML`.
11. **Token & Key Masking**: Never print or log a full token or any private key.
12. **Honesty**: Be honest: describe the project as a prototype. Do not call it "secure" or "unhackable".
