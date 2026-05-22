# Axxess Compliance Engine (ACE) — Engineer Quick Start

## What this is

A pair of PowerShell scanners that check your workstation for evidence of two recent npm supply-chain attacks:

- **ACE** — the March 31, 2026 Axios NPM supply-chain compromise (malicious `plain-crypto-js` dependency in `axios` v1.14.1 / v0.30.4).
- **Mini Shai-Hulud (MSH)** — the April–May 2026 npm worm.

Each scan takes 1–5 minutes depending on how many `node_modules` trees you have. Results submit to a central dashboard your manager monitors.

---

## What you need

- **Windows** 10 / 11 / Server 2019+
- **PowerShell 7+** — install from <https://aka.ms/powershell-release> if you don't have it. To check: open the Start Menu and search for `pwsh`. If it doesn't exist, install it.
- The submission password (below).

---

## Submission password

```
<PASTE_PASSWORD_HERE>
```

You'll be prompted for this twice — once per scanner. Same password for both.

---

## Step 1 — Download the scanner

**Option A — Browser (easiest)**

1. Go to <https://github.com/mbfromit/ACE>
2. Click the green **Code** button → **Download ZIP**
3. Extract the ZIP somewhere convenient, e.g. `C:\Tools\ACE`

**Option B — Git (if you already have it)**

```powershell
git clone https://github.com/mbfromit/ACE.git C:\Tools\ACE
```

---

## Step 2 — Run the Axios scanner

Open **PowerShell 7** (`pwsh` from the Start Menu — *not* the older Windows PowerShell 5 in the blue window).

```powershell
cd C:\Tools\ACE
.\Invoke-ACE.ps1
```

You will see:

1. A banner listing the folders that will be scanned. Press **ENTER** to start, or `Q` to cancel.
2. A prompt for the **submission password**. Paste the password from the top of this doc and press **ENTER**. The script verifies it against the server before scanning.
3. Progress output as the scanner runs its 10 checks (1–5 min).

When the scan finishes:
- A log file lands at `C:\Logs\ACE-<your-hostname>-<timestamp>.log`
- An HTML report opens in your browser
- Results are submitted to the dashboard automatically

---

## Step 3 — Run the Mini Shai-Hulud scanner

In the same PowerShell window:

```powershell
.\Invoke-MiniShaiHulud.ps1
```

Same prompts. Same password.

---

## Where to see results

Manager dashboard: **<https://mbfromit.com/ratcatcher/dashboard>**

Your submissions show up tagged by hostname + campaign.

---

## If you see a COMPROMISED verdict

**Don't panic. Don't delete anything.** Take a screenshot of the HTML report, save the log file from `C:\Logs\`, and ping your manager or the security team immediately. The reports are forensic evidence — leave them intact.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `pwsh` not recognized in PowerShell | You have Windows PowerShell 5 only — install PowerShell 7 from the link above. |
| `Incorrect password` after pasting | Confirm there are no leading/trailing spaces. Re-copy the password from this doc. |
| HTML report didn't open | Find the latest `.html` file in `C:\Logs\` and double-click it. |
| Script blocked by execution policy | Run once per session: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Scan is taking forever | Some dev workstations have very large `node_modules` trees — let it run. If it's been >15 min, ping your manager. |

---

*Questions? Ping your manager or post in the team chat.*
