# Cantina Contest Ranking Calculator

Calculate prize‑pool payouts for ongoing **Cantina** web3 audit competitions, right from the command line.

| Feature | Description |
|---------|-------------|
| **Live data** | Pulls confirmed & duplicate findings via Cantina’s private API. |
| **Customisable** | Override pot size, ignore certain findings, force severities or duplicate groupings, and toggle Early‑Bird bonus logic. |
| **Transparent math** | Prints vulnerability‑level breakdown, manual‑override summary, and a sortable payout table. |
| **No spreadsheet pain** | One command = clean, share‑ready output. |

---

## Installation

```bash
git clone https://github.com/<your‑handle>/cantina‑contest‑ranking.git
cd cantina‑contest‑ranking
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Quick start

1. **Edit `cantina_contest_ranking.py`**  
   * Set `Config.REPO_ID` to the UUID of the Cantina repository you’re tracking.  
   * Paste your session token into `Config.COOKIE` (format: `auth_token=...`).  
   * Adjust `DEFAULT_PRIZE_POT` or keep the command‑line override handy.

2. **Run**  
   ```bash
   python cantina_contest_ranking.py
   ```

3. **Example with options**

   ```bash
   # 200 k pot, ignore findings 10 & 203, force #677 to HIGH, enable Early‑Bird
   python cantina_contest_ranking.py \
       --pot 200000 \
       --ignore-numbers 10 203 \
       --severity-override 677:high \
       --early-bird
   ```

---

## CLI reference

| Flag | Purpose |
|------|---------|
| `-p, --pot AMOUNT` | Override total prize pot. |
| `-i, --ignore-numbers NUM …` | Ignore specific finding numbers. |
| `-s, --severity-override ID:SEV` | Force a finding (and its dupes) to a new severity. Repeatable. |
| `-d, --manual-dupe ORIG:DUP1,DUP2` | Manually mark findings as duplicates. Repeatable. |
| `-e, --early-bird / -ne, --no-early-bird` | Toggle 30 % first‑finder bonus. |

---

## Security note

Your Cantina `auth_token` **grants account access**.  
Store it securely (e.g. pass via environment variable and load it inside `Config.COOKIE`).  
Never commit real tokens to a public repo.


Made with ☕ by **ZeroCipher002** – pull requests welcome!
