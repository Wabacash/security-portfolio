# Phishing Email Analysis — "Membership Has Expired" / Fake Prime Notice

**Analyst:** Antony
**Date analyzed:** 2026-07-29
**Tools used:** MXToolbox Header Analyzer, MXToolbox DMARC Lookup

---

## 1. Executive Summary

A phishing email impersonating an "Account Prime" membership service was delivered to a Gmail inbox. The message abuses **Mandrill (mandrillapp.com)**, a legitimate transactional email service, to send from a throwaway `.study` domain. SPF and DKIM both technically **pass**, but neither is aligned to the visible `From` domain, so DMARC correctly evaluates to **fail**. This is a textbook case of an attacker exploiting a reputable ESP's sending infrastructure to slip past reputation-based filters while relying on domain misalignment to remain otherwise undetected by unaware recipients.

**Verdict:** Malicious / Phishing (brand impersonation, credential-harvesting lure pattern)

---

## 2. Header / Envelope Details

| Field | Value |
|---|---|
| From (display) | `Prime <jnilpodsgekyimfoquio@delgaop.study>` |
| To | `antoine@delgaop.study` (X-Original-To: `antoine@delgaop.study`) |
| Delivered-To | `antoznjeru@gmail.com` |
| Return-Path | `<return@kabzrrevvjsuiltmuezhdo.casacam.net>` |
| Subject | `Membership Has Expiired ! Your Accouunt Prime Will-Be Removed Today` |
| Message-ID | `<6a679913.176abf24.20afeb.dc12SMTPIN_ADDED_BROKEN@mx.google.com>` |
| Date | Sun, 26 Jul 2026 15:09:46 +0000 |
| Sending ESP | Mandrill (mandrillapp.com, subaccount `mte1`) |
| Relay delay | 95,705 seconds (~26.6 hours) between hops |

**Red flags in the visible metadata alone:**
- Deliberate misspellings ("Expiired," "Accouunt," "Will-Be") — classic filter-evasion technique for subject-line keyword scanners.
- Urgency/loss-aversion framing ("Removed Today").
- The `From` and `To` domains are the same (`delgaop.study`) despite the mail actually going to a Gmail address — a sign of a spoofed/catch-all sending domain rather than a genuine 1:1 correspondence.
- `Message-ID` string contains `SMTPIN_ADDED_BROKEN`, indicating Google's mail pipeline flagged/patched a malformed or missing Message-ID — often seen on spam/phish infrastructure that doesn't generate RFC-compliant headers.
- Random alphanumeric subdomain on the bounce/return domain (`kabzrrevvjsuiltmuezhdo.casacam.net`) — typical of algorithmically generated phishing infrastructure.

---

## 3. Authentication Analysis (SPF / DKIM / DMARC)

This is the most instructive part of the case: **all three checks look "green" in isolation, but DMARC still fails** because of misalignment.

| Check | Result | Detail |
|---|---|---|
| SPF | ✅ Pass (but unaligned) | `spf=pass` for `return@kabzrrevvjsuiltmuezhdo.casacam.net` (62.210.27.128) — this is the **Return-Path/envelope domain**, not the visible `From` domain (`delgaop.study`) |
| DKIM | ✅ Pass (but unaligned) | `dkim=pass header.i=@mandrillapp.com` — signed by Mandrill's sending infrastructure, **not** `delgaop.study`. A second signature attempt for `header.i=@delgaop.study` returns `dkim=permerror (no key for signature)` — the attacker's own domain has no valid DKIM key published |
| DMARC | ❌ **Fail** | `dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=delgaop.study` |

**Why DMARC fails despite SPF/DKIM passing:** DMARC requires *alignment* — the domain that SPF or DKIM authenticates must match (or be a subdomain of) the visible `From:` header domain. Here:
- SPF authenticated `casacam.net`, not `delgaop.study` → **SPF misaligned**
- DKIM authenticated `mandrillapp.com`, not `delgaop.study` → **DKIM misaligned**
- Result: DMARC fails on alignment even though both underlying mechanisms technically passed.

**Why this still got delivered:** `delgaop.study`'s own DMARC record is:
```
v=DMARC1; p=none; sp=none;
```
`p=none` means "monitor only, take no enforcement action." A `p=quarantine` or `p=reject` policy on the sender's domain would have caused this message to be quarantined or rejected outright regardless of alignment failure. This is either a domain the attacker registered with no intention of ever enforcing DMARC, or a domain they don't control DNS enforcement expectations for — either way, it did them no favors defensively but cost the recipient nothing in protection.

---

## 4. Infrastructure / Relay Path

| Hop | From | By | Notes |
|---|---|---|---|
| 1 | 163.172.194.117 | mandrillapp.com | ⚠️ Flagged on a blacklist check |
| 2 | mta008-md-use2.delv.a.intuit.com | mail180-1.suw31.mandrillapp.com | ESMTP, clean |
| 3 | mail180-1.suw31.mandrillapp.com | asp-relay-pe.jellyfish.systems | TLS 1.3, clean |
| 4 | asp-relay-pe.jellyfish.systems | relay.privateemail.services | ⚠️ Flagged on a blacklist check |
| ... | (dovecot proxy/backend cluster hops) | ... | Internal mail cluster routing |
| final | — | mx.google.com | Delivered to Gmail |

Two of the observed hops returned positive blacklist hits, and the originating IP (163.172.194.117) is the first hop with no upstream "From" — consistent with an attacker-controlled or compromised sending host feeding into Mandrill's platform (i.e., abusing a legitimate ESP account rather than standing up dedicated phishing infrastructure).

---

## 5. Indicators of Compromise (IOCs)

```
From domain:        delgaop.study
Return-Path domain:  kabzrrevvjsuiltmuezhdo.casacam.net
Sending IP:          163.172.194.117
Relay host:          asp-relay-pe.jellyfish.systems
Relay host:          relay.privateemail.services
ESP abused:          mandrillapp.com (subaccount: mte1, MD user: md_31641264)
Feedback-ID:         31641264:31641264:20260726:md
Subject line:        Membership Has Expiired ! Your Accouunt Prime Will-Be Removed Today
```

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Phishing | T1566 | Bulk email lure impersonating a "Prime" membership brand |
| Spearphishing Link (sub-technique, inferred) | T1566.002 | Urgency-based subject designed to drive a click; body/link not captured in this header-only analysis |
| Impersonation | T1656 | Spoofed brand identity ("Prime") and domain crafted to look legitimate at a glance |
| Compromise/Abuse of Trusted Infrastructure | T1584 / T1102 | Legitimate ESP (Mandrill) leveraged to inherit sender reputation and bypass reputation-based filtering |
| Domain misspelling / evasion | T1036 (Masquerading, adjacent) | Deliberate typos to evade keyword-based content filters |

---

## 7. Recommendations

- **For the recipient's domain (if this were an org asset):** move DMARC policy from `p=none` toward `p=quarantine`, then `p=reject`, once legitimate sending sources are fully inventoried.
- **Detection rule idea:** flag inbound mail where `dmarc=fail` AND the `Authentication-Results` header shows SPF/DKIM domains that don't match the visible `From` domain — this is a stronger signal than SPF/DKIM pass/fail alone.
- **User awareness angle:** this sample is a good training example precisely *because* SPF and DKIM both "pass" — it demonstrates why end users (and even some junior analysts) shouldn't treat SPF/DKIM pass as a green light without checking alignment.
- **Report vector:** Mandrill provides its own abuse reporting endpoint (`X-Report-Abuse` header) — reporting abused ESP accounts helps get sending privileges revoked at the platform level.

---

*Analysis performed for personal SOC/threat-intel practice — TryHackMe / Blue Team Labs Online adjacent workflow.*
