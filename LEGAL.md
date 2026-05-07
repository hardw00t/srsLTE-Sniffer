# Legal & Ethical Use

This project captures, decodes, and analyses LTE control-plane traffic — most
notably paging requests carrying IMSI / S-TMSI subscriber identifiers. In most
jurisdictions, **passive interception of cellular control traffic is regulated
or outright illegal** (e.g. the US Wiretap Act, EU electronic-communications
directives, the UK Investigatory Powers Act, Singapore's TIA, etc.).

The code is published for:

1. **Authorised security research** — pentest engagements with written scope
   covering RF, lab tests using your own private eNB, academic study under
   institutional review.
2. **Defensive use** — the rogue-eNB detector mode (`srslte-sniffer detect`)
   is intended for blue-team monitoring of your own networks.
3. **Education** — understanding how IMSI catchers work so they can be
   defended against.

The maintainers do not condone — and explicitly disclaim responsibility for —
use against networks, subscribers, or persons without consent.

## Runtime safeguards

- Capture commands require `--i-have-authorization` to run. The flag is
  intentionally awkward to pass.
- IMSI / M-TMSI are SHA-256-hashed by default. Raw values are only emitted
  when `--unsafe-raw` is passed.
- The SQLite store has a `purge` command for incident response.
- A `LEGAL_BANNER` is printed on every capture-mode start.

## Jurisdiction-specific notes

| Region | Notes |
|--------|-------|
| US | 18 U.S.C. § 2511 (Wiretap Act). Lab/private-network use only. |
| EU | Directive 2002/58/EC. Per-state variation; check national rules. |
| UK | Investigatory Powers Act 2016. RIPA s.3 lawful-interception exemptions are narrow. |
| SG | Telecommunications Act, sections 43/44. Equipment licensing also applies. |

If in doubt, **don't transmit, don't capture, set up a private eNB**.
