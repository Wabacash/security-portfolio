# Website Investigation: Reconnaissance & Information Disclosure

**Target:** Acme IT Support (simulated environment)
**Scope:** Client-side and server-side reconnaissance techniques used to enumerate a web application's attack surface prior to exploitation.
**Rooms covered:** TryHackMe *Walking An Application*, *Content Discovery*

## Objective

Before any exploitation begins, an attacker (or auditor) needs to map what's actually exposed. This exercise walked through the standard reconnaissance workflow used to profile a web application: reading what the site tells you directly (source, comments, headers), and finding what it doesn't mean to tell you (hidden paths, disabled controls, leftover files).

## Methodology & Findings

### 1. Source code review
Viewing page source surfaced a developer comment pointing to an unlinked beta homepage (`/new-home-beta`), and a footer disclosing the exact web framework and version (THM Framework v1.2) powering the site.

**Takeaway:** Comments and generator/footer tags are routinely left in production by developers. Framework/version disclosure is a direct input into vulnerability research — the next step was checking that framework's own changelog.

### 2. Version-to-vulnerability mapping
Cross-referencing the disclosed framework version against its public changelog showed that v1.3 patched an issue where the backup process wrote a publicly readable archive (`/tmp.zip`) into the web root. Since the target was still on v1.2, the unpatched backup file was still reachable and downloadable directly.

**Takeaway:** Fingerprint → changelog → patch status is a fast, low-noise way to identify exposure without active exploitation. This mirrors real vulnerability research against CMS/framework-driven sites.

### 3. Client-side access controls (CSS-based paywall)
A "premium content" article was gated using a `<div class="premium-customer-blocker">` with `display: block` applied purely via CSS. Using the browser's element inspector, toggling that property to `display: none` removed the overlay and exposed the full article — including a second flag embedded in a sibling element (`imgFlag`).

**Takeaway:** Content "protected" only by front-end CSS is not actually protected — the data ships to the browser regardless. Any access-control logic (paid content, staff-only pages) must be enforced server-side.

### 4. robots.txt and sitemap.xml disclosure
- `robots.txt` explicitly disallowed crawlers from `/staff-portal` — inadvertently pointing directly at a path the site owner wanted hidden.
- `sitemap.xml` listed a secret area (`/s3cr3t-area`) never linked anywhere in the site's navigation, plus a set of parameterised article endpoints (`?id=1,2,3`) worth testing for IDOR/injection later.

**Takeaway:** Both files are meant to help search engines but function as a free directory listing for attackers. Sensitive paths should never be referenced in either file — restriction should be enforced through authentication, not by omission from a public index.

### 5. HTTP response header disclosure
Inspecting response headers (Network tab → Headers) revealed a custom `X-FLAG` header returned on every request — a stand-in for the kind of custom debug/versioning headers organisations sometimes leave enabled in production.

### 6. Admin portal discovery and default credentials
The framework's own documentation (found by following the footer link) disclosed the fixed administration login path (`/thm-framework-login`) and stated default credentials (`admin` / `admin`), with a note to change them post-install — which had not been done on the target.

**Takeaway:** Vendor/framework documentation is a legitimate and frequently overlooked recon source. Default credentials left unchanged after install remain one of the most common real-world footholds.

### 7. Virtual host enumeration
Used `gobuster` in vhost mode against the target IP to enumerate virtual hosts bound to `acmeitsupport.thm`:

```bash
gobuster vhost -u "http://10.48.152.84" \
  --domain acmeitsupport.thm \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain --exclude-length 250-320 -o vhost_results.txt
```

3 virtual hosts responded with HTTP 200, confirming additional attack surface not visible from the primary domain alone.

## Tools Used
- Firefox Developer Tools (Inspector, Network)
- `gobuster` (DNS and VHOST enumeration modes)
- Manual source review / `view-source:`

## Remediation Summary

| Finding | Recommendation |
|---|---|
| Framework/version disclosed in footer & comments | Strip debug comments and version banners from production builds |
| Outdated framework version with known file exposure | Patch to latest version; audit web root for stray backup files |
| Paywall enforced client-side only | Enforce entitlement checks server-side before rendering content |
| Sensitive paths listed in robots.txt/sitemap.xml | Remove sensitive paths from both files; rely on authentication, not obscurity |
| Custom debug header in responses | Strip non-essential custom headers before production deployment |
| Default admin credentials unchanged | Enforce credential rotation on first login; disable default accounts |
| Multiple vhosts exposed | Confirm each vhost is intentionally public; restrict/segment internal-only hosts |