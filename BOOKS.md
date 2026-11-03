# Reading List & Learning Path

**179 book / course / certification links** live in `by-category/12-books-courses.md` and in the
Antigravity rule `21-books-courses-part{1,2}.md`. This document is the *ordered, annotated*
version — what to read, in what sequence, and why.

✓ = link returned HTTP 200 when collected · ~ = link is behind anti-bot protection (Wiley, Packt,
O'Reilly all block automated requests) but resolves normally in a browser.

---

## The short answer

If you only buy three books: **Bug Bounty Bootcamp** (structure), **Real-World Bug Hunting**
(pattern recognition), **Hacking APIs** (where the modern enterprise attack surface actually is).
Then stop buying books and do 150 PortSwigger Academy labs.

---

## Track 0 — Free, and better than most paid material

| Resource | Why |
|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) ✓ | ~150 hands-on labs by the authors of *The Web Application Hacker's Handbook*. The single highest-value free resource in web security. Do every lab. |
| [Web Hacking 101](https://leanpub.com/web-hacking-101) ✓ | Peter Yaworski's free book. Case-study driven; reads like a tour of real paid findings. |
| [HackTricks](https://book.hacktricks.wiki/en/) ~ | Enormous practical technique reference. Cloudflare-protected but fine in a browser. 1,159 individual pages are indexed in this corpus. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) ✓ | Payloads and bypass techniques by vulnerability class. |
| [Hacker101](https://www.hacker101.com/) ✓ | HackerOne's free course, plus a [CTF](https://ctf.hacker101.com) ✓ that unlocks private program invitations. |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/) ✓ | The free, canonical web testing methodology. Read it as a checklist, not a novel. |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) ✓ | Concise per-topic guidance. |
| [pwn.college](https://dojo.pwn.college/) ✓ | Free, structured, rigorous systems/exploitation curriculum from ASU. Best free binary track in existence. |
| [SEED Labs](https://seedsecuritylabs.org/labs.html) ✓ | University-quality hands-on security labs, free. |
| [SANS Reading Room](https://sans.org/white-papers) ✓ | Thousands of free whitepapers. |
| [Stanford CS253 Web Security](https://cs253.stanford.edu/) ✓ | Free lecture material on web security fundamentals. |
| [GTFOBins](https://gtfobins.github.io/) ✓ / [LOLBAS](https://lolbas-project.github.io/) ✓ | Unix and Windows privilege-escalation binary references. Bookmark both. |
| [DEF CON Media Server](https://media.defcon.org/) ✓ | Every DEF CON talk ever recorded, free. |

---

## Track 1 — Bug bounty specific (read in this order)

### 1. Bug Bounty Bootcamp — Vickie Li, No Starch Press
[nostarch.com/bug-bounty-bootcamp](https://nostarch.com/bug-bounty-bootcamp) ✓

The best structured path from zero to first payout. Covers recon, the common web vulnerability
classes, report writing, and the *business* of bug bounty (program selection, communication,
handling duplicates and N/As). Read it cover to cover before you submit anything.

### 2. Real-World Bug Hunting — Peter Yaworski, No Starch Press
[nostarch.com/bughunting](https://nostarch.com/bughunting) ✓

Organised by vulnerability class, built entirely from real disclosed HackerOne reports. Its real
value is **pattern recognition**: after this you start seeing where classes hide rather than
searching randomly. Read it alongside HackerOne hacktivity.

### 3. Hacking APIs — Corey Ball, No Starch Press
[nostarch.com/hacking-apis](https://nostarch.com/hacking-apis) ✓

**The most under-read, highest-ROI book on this list.** Large enterprises are overwhelmingly API
surface: mobile backends, partner integrations, internal GraphQL, BFF layers. Most hunters never
leave the browser. Corey Ball's API discovery and abuse methodology is directly monetisable and
the competition is far thinner than on the marketing website.

Dana Epp's independent reading list for API hackers puts this first
[1](https://danaepp.com/5-books-every-api-hacker-should-read).

### 4. A Bug Hunter's Diary — Tobias Klein, No Starch Press
[nostarch.com/bughunter](https://nostarch.com/bughunter) ✓

Deep, low-level, and harder than the above. Auditing real software (browsers, PDF readers, media
codecs, kernels). This is the book that changes *how you read code*. Read it after you have some
reps, not before.

### 5. Black Hat GraphQL — Dolev Farhi & Nick Aleks, No Starch Press
[nostarch.com/black-hat-graphql](https://nostarch.com/black-hat-graphql) ✓

GraphQL is now default in modern enterprise stacks, and its security model is poorly understood
by both defenders and hunters. Introspection, batching abuse, query depth/complexity DoS, field
suggestion leakage, alias-based rate-limit bypass.

### 6. Bug Bounty Hunting for Web Security — Mohit Kumar, Apress
[link.springer.com/book/10.1007/978-1-4842-5391-5](https://link.springer.com/book/10.1007/978-1-4842-5391-5) ✓

### 7. Bug Bounty Hunting Essentials — Carlos Avila, André Oliveira, Jorge Horta, Packt
[packtpub.com](https://packtpub.com/product/bug-bounty-hunting-essentials/9781788626897) ~

### 8. Hands-On Bug Hunting for Penetration Testers — Joseph Marshall
[packtpub.com](https://packtpub.com/product/hands-on-bug-hunting-for-penetration-testers/9781484240960) ~

### 9. Getting started without a background
Andy Gill's *Breaking into Information Security* was the standard free on-ramp but is no longer
published. Its replacements, all free and all live:
[Hacker101](https://www.hacker101.com/) ✓ (HackerOne's own course, plus a
[CTF](https://ctf.hacker101.com) ✓ that unlocks private program invitations),
the [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs) ✓, and
[pwn.college](https://pwn.college/) ✓ for systems depth.

> **Consensus check.** Independent 2026 reading lists converge on the same core: Bug Bounty
> Bootcamp, Real-World Bug Hunting, A Bug Hunter's Diary, and The Web Application Hacker's
> Handbook [5](https://www.cybershelf.org/en/guides/best-books-for-bug-bounty-hunters-2026)
> [4](https://infosecwriteups.com/bugbounty-mastering-the-basics-along-with-resources-part-4-f424a26c6ef6).

---

## Track 2 — The foundations

### The Web Application Hacker's Handbook, 2e — Stuttard & Pinto, Wiley
[wiley.com](https://wiley.com/en-us/The+Web+Application+Hackers+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472) ~
· [alt.](http://wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html) ~

Still the conceptual foundation of web security. Published 2011, so the *tooling* is obsolete and
the *thinking* is not. In practice, **read the free PortSwigger Academy instead** — same authors,
continuously updated, with labs. Buy the book only if you want the linear narrative.

### The Hacker Playbook 3 — Peter Kim
[amazon.com](https://amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689) ✓ (Advanced Penetration Testing, the closest live equivalent)
· [The Hacker Playbook 1](http://amazon.com/The-Hacker-Playbook-Practical-Penetration/dp/1494932636) ✓

Campaign-oriented: how to chain findings into an actual compromise rather than reporting isolated
bugs. This is the mental model behind impact escalation (`STRATEGY.md` §4).

### Penetration Testing — Georgia Weidman, No Starch Press
[nostarch.com/pentesting](https://nostarch.com/pentesting) ✓

### Hacking: The Art of Exploitation, 2e — Jon Erickson, No Starch Press
[nostarch.com/hacking2E](https://nostarch.com/hacking2E) ✓

### Gray Hat Hacking, 6e — McGraw Hill
[mheducation.com](https://mheducation.com/highered/product/gray-hat-hacking-ethical-hacker-s-handbook-sixth-edition-england/M9781264268405.html) ✓

### Threat Modeling: Designing for Security — Adam Shostack, Wiley
[wiley.com](https://wiley.com/en-us/Threat+Modeling%3A+Designing+for+Security-p-9781118809990) ~
· [threatmodelingbook.com](https://threatmodelingbook.com/) ✓

Unusual pick for a bug bounty list, and worth it. Threat modelling teaches you to enumerate trust
boundaries and attacker capabilities *systematically* — which is precisely how you find business
logic bugs that no scanner and no checklist will ever surface.

---

## Track 3 — Automation (how you scale past one-target-at-a-time)

| Book | Link |
|---|---|
| **Black Hat Python, 2e** — Seitz & Arnold | [amazon.com](http://amazon.com/Black-Hat-Python-Programming-Pentesters/dp/1593275900) ✓ |
| **Black Hat Go** — Steele, Patten, Kottmann | [nostarch.com/blackhatgo](https://nostarch.com/blackhatgo) ✓ |
| **Gray Hat Python** | [amazon.com](https://amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921) ✓ |
| **Full Stack Python Security** | [manning.com](https://manning.com/books/full-stack-python-security) ✓ |
| **Securing DevOps** | [manning.com](https://manning.com/books/securing-devops) ✓ |

Once your recon pipeline is automated, your effective hunting hours triple. This is the difference
between part-time and full-time income.

---

## Track 4 — API, auth & cloud (where enterprise money is)

| Book | Link |
|---|---|
| **API Security in Action** | [manning.com](https://manning.com/books/api-security-in-action) ✓ |
| **Understanding API Security** | [manning.com](https://manning.com/books/understanding-api-security) ✓ |
| **OAuth 2 in Action** | [manning.com](https://manning.com/books/oauth-2-in-action) ✓ |
| **Grokking Web Application Security** | [manning.com](https://manning.com/books/grokking-web-application-security) ✓ |
| **AWS Security** | [manning.com](https://manning.com/books/aws-security) ✓ |
| **Azure Security, 2e** | [manning.com](https://manning.com/books/azure-security-2) ✓ |
| **The Art of Network Penetration Testing** | [manning.com](https://manning.com/books/the-art-of-network-penetration-testing) ✓ |
| **Spring Security in Action, 2e** | [manning.com](https://manning.com/books/spring-security-in-action-second-edition) ✓ |

OAuth/OIDC misconfiguration is a Tier-S finding at essentially every large enterprise — token
leakage via open redirect, `redirect_uri` bypass, confused deputy, scope escalation. Very few
hunters do this well.

---

## Track 5 — Binary, reverse engineering & exploit development

For the Apple/Google/Microsoft-tier payouts ($350k–$2M), this is the required track.

| Book | Link |
|---|---|
| **Practical Binary Analysis** — Dennis Andriesse | [nostarch.com/binaryanalysis](https://nostarch.com/binaryanalysis) ✓ |
| **Practical Reverse Engineering** — Dang, Gazet, Bachaalany | [wiley.com](https://wiley.com/en-us/Practical+Reverse+Engineering%3A+x86%2C+x64%2C+ARM%2C+Windows+Kernel%2C+Reversing+Tools%2C+and+Obfuscation-p-9781118787311) ~ |
| **The IDA Pro Book, 2e** — Chris Eagle | [nostarch.com/idapro2.htm](https://nostarch.com/idapro2.htm) ✓ |
| **The Beginner's Guide to IDAPython** — Alexander Hanel | [leanpub.com/IDAPython-Book](https://leanpub.com/IDAPython-Book) ✓ |
| **Practical Malware Analysis** — Sikorski & Honig | [nostarch.com/malware](https://nostarch.com/malware) ✓ |
| **The Shellcoder's Handbook, 2e** | [amazon.com](https://amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X) ✓ |
| **The Art of Memory Forensics** | [amazon.com](https://amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098) ✓ |
| **Fuzzing: Brute Force Vulnerability Discovery** | [amazon.com](https://amazon.com/Fuzzing-Brute-Force-Vulnerability-Discovery/dp/0321446119) ✓ |
| **Fuzzing for Software Security Testing and Quality Assurance** | [amazon.com](https://amazon.com/Fuzzing-Software-Security-Testing-Assurance/dp/1608078507) ✓ |
| **Advanced Penetration Testing** — Wil Allsopp | [amazon.com](https://amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689) ✓ |
| **Advanced Exploit Development (SANS SEC660/760)** | [sans.org](https://sans.org/course/advanced-exploit-development-penetration-testers) ✓ |

---

## Track 6 — Mobile

| Book | Link |
|---|---|
| **The Mobile Application Hacker's Handbook** | [wiley.com](https://wiley.com/en-us/The+Mobile+Application+Hacker%27s+Handbook-p-9781118958500) ~ |
| **Android Hacker's Handbook** | [amazon.com](https://amazon.com/Android-Hackers-Handbook-Joshua-Drake/dp/111860864X) ✓ |
| **iOS Hacker's Handbook** | [amazon.com](https://amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123) ✓ |
| **Hacking and Securing iOS Applications** | [amazon.com](https://amazon.com/Hacking-Securing-iOS-Applications-Hijacking/dp/1449318746) ✓ |
| **Android Security Internals** — Jonathan Levin | [oreilly.com](https://oreilly.com/library/view/android-security-internals/9781457185496) ~ |
| **OWASP MASTG** (free, replaces most of the above) | [mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/) ✓ |

The **OWASP MASTG** is free, current, and better than any of the print mobile books. Start there;
use the Wiley handbooks for depth on platform internals.

---

## Track 7 — Adjacent domains worth one book each

| Domain | Book | Link |
|---|---|---|
| IoT / hardware | Practical IoT Hacking | [nostarch.com/practical-iot-hacking](https://nostarch.com/practical-iot-hacking) ✓ |
| Automotive | The Car Hacker's Handbook | [nostarch.com/carhacking](https://nostarch.com/carhacking) ✓ |
| Social engineering | Practical Social Engineering | [nostarch.com/practical-social-engineering](https://nostarch.com/practical-social-engineering) ✓ |
| Cryptography | Real World Cryptography | [manning.com](https://manning.com/books/real-world-cryptography) ✓ |
| Threat hunting | Cyber Threat Hunting | [manning.com](https://manning.com/books/cyber-threat-hunting) ✓ |
| Databases | The Database Hacker's Handbook | [wiley.com](https://wiley.com/en-us/The+Database+Hacker%27s+Handbook%3A+Defending+Database+Servers-p-9780764578014) ~ |
| Browsers | The Browser Hacker's Handbook | [wiley.com](https://wiley.com/en-us/The+Browser+Hacker%27s+Handbook-p-9781118662090) ~ |
| Blue team | Applied Incident Response | [amazon.com](https://amazon.com/Applied-Incident-Response-Steve-Anson/dp/1119560268) ✓ |
| Field reference | RTFM: Red Team Field Manual | [amazon.com](http://amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504) ✓ |
| Field reference | Operator Handbook | [amazon.com](https://amazon.com/Operator-Handbook-Team-OSINT-Reference/dp/B085RR67H5) ✓ |
| Career | Cyber Security Career Guide | [manning.com](https://manning.com/books/cyber-security-career-guide) ✓ |

---

## Certifications — what actually signals skill

| Cert | Value for bug bounty | Link |
|---|---|---|
| **Burp Suite Certified Practitioner (BSCP)** | High — directly tests web exploitation skill | [portswigger.net/web-security/certification](https://portswigger.net/web-security/certification) ✓ |
| **PNPT** (TCM Security) | High — realistic, practical, well-regarded, cheap | [certifications.tcm-sec.com/pnpt](https://certifications.tcm-sec.com/pnpt) ✓ |
| **OSCP** | Moderate-high — HR filter, teaches persistence | [offsec.com/courses/pen-200](https://www.offsec.com/courses/pen-200/) ✓ |
| **OSWE / WEB-300** | High for white-box web | [offsec.com](https://www.offsec.com/) ✓ |
| **eWPTX** | Moderate | [my.ine.com](https://my.ine.com) ✓ |
| **CRTP** | Moderate — AD-focused | [alteredsecurity.com/adlab](https://www.alteredsecurity.com/adlab) ✓ |
| **Security+ / CEH** | Low for hunting; useful only as an HR gate | [comptia.org](https://comptia.org/certifications/security) ✓ · [eccouncil.org](https://eccouncil.org/programs/certified-ethical-hacker-ceh) ✓ |

**Honest assessment:** certifications do not earn bounties. **Disclosed reports do.** A public
track record on HackerOne/Bugcrowd — reports, reputation, writeups — is worth more to every
employer in this space than any certificate. If you must pick one, pick BSCP or PNPT because they
test the actual skill.

---

## A 12-month sequence

| Months | Do this |
|---|---|
| **1–2** | Hacker101 + PortSwigger Academy *Apprentice* labs → Bug Bounty Bootcamp.  Start a notes system now. |
| **3–4** | Real-World Bug Hunting + 20 HackerOne disclosed reports per week. All PortSwigger *Practitioner* labs. Build your recon pipeline (`STRATEGY.md` §5). |
| **5–6** | Hacking APIs + Black Hat GraphQL. Set up the Tier-2 local lab (`LABS.md`). First 10 reports on large-surface VDPs — expect duplicates, learn triage. |
| **7–8** | Move to Archetype-3 programs (responsive, mid-size, paid). Work Tier-S classes deliberately: access control, auth, SSRF, race conditions. All PortSwigger *Expert* labs. |
| **9–10** | A Bug Hunter's Diary. Pick a specialisation (API / mobile / cloud / AI-LLM). Automate everything you found yourself doing twice. |
| **11–12** | If binary work interests you: pwn.college + Practical Binary Analysis. Otherwise: deepen the specialisation, enter CTFs for reps, and start writing up your own findings. |

Throughout: one CTF per month for reps, one conference talk per week
(`by-category/16-youtube-media.md`, 360 links), and a weekly review of your own false leads —
that review is where the skill actually compounds.
