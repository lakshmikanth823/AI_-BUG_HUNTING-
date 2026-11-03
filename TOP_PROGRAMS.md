# Enterprise Bug Bounty Program Targeting Guide

**Source:** live program metadata for **946 programs** scraped from HackerOne, Bugcrowd, Intigriti and YesWeHack ([arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)).

**Machine-readable version:** `data/programs-ranked.csv` — regenerate any time with `cd work && python3 programs.py`. Program scope, payouts and responsiveness change monthly; this snapshot is dated **2026-10-29**.

> **Authorisation first.** Every entry below is a pointer to a *program page*, not a target. Read the scope document, out-of-scope list, rate limits and safe-harbor terms before sending a single packet. Scope changes without notice.

---

## Platform coverage

| Platform | Programs indexed |
|---|---|
| HackerOne | 450 |
| Bugcrowd | 297 |
| Intigriti | 143 |
| YesWeHack | 56 |
| **Total** | **946** |

414 of them publish a maximum bounty. HackerOne does not expose payout amounts through this feed, so it is ranked instead by **response efficiency** and **bounty-eligible asset count** — both better predictors of actual earnings than a headline ceiling.

---

## 1. Highest published maximum payouts

| # | Program | Max payout | Platform | In-scope assets |
|---|---|---|---|---|
| 1 | [OpenSea Managed Bug Bounty Program](https://bugcrowd.com/engagements/opensea) | **3,000,000 USD** | Bugcrowd | 11 |
| 2 | [Swiss Post - E-Voting](https://yeswehack.com/programs?search=Swiss%20Post%20-%20E-Voting) | **230,000 USD** | YesWeHack | 5 |
| 3 | [Fireblocks MPC Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/fireblocks-mbb-og2) | **150,000 USD** | Bugcrowd | 1 |
| 4 | [T-Mobile](https://bugcrowd.com/engagements/t-mobile) | **133,700 USD** | Bugcrowd | 76 |
| 5 | [SpaceX/Starlink](https://bugcrowd.com/engagements/spacex) | **100,000 USD** | Bugcrowd | 1 |
| 6 | [Tesla](https://bugcrowd.com/engagements/tesla) | **100,000 USD** | Bugcrowd | 11 |
| 7 | [Sophos](https://bugcrowd.com/engagements/sophos) | **80,000 USD** | Bugcrowd | 18 |
| 8 | [Okta](https://bugcrowd.com/engagements/okta) | **75,000 USD** | Bugcrowd | 21 |
| 9 | [Auth0 by Okta](https://bugcrowd.com/engagements/auth0-okta) | **50,000 USD** | Bugcrowd | 26 |
| 10 | [Zendesk Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/zendesk) | **50,000 USD** | Bugcrowd | 6 |
| 11 | [Doctolib](https://yeswehack.com/programs?search=Doctolib) | **50,000 USD** | YesWeHack | 9 |
| 12 | [Kiteworks Public Bug Bounty Program](https://yeswehack.com/programs?search=Kiteworks%20Public%20Bug%20Bounty%20Program) | **50,000 USD** | YesWeHack | 12 |
| 13 | [AXIS OS](https://bugcrowd.com/engagements/axis-os-public) | **40,000 USD** | Bugcrowd | 1 |
| 14 | [Aiven Managed Bug Bounty](https://bugcrowd.com/engagements/aiven-mbb-og) | **25,000 USD** | Bugcrowd | 16 |
| 15 | [Bullish Exchange](https://bugcrowd.com/engagements/bullish-exchange) | **25,000 USD** | Bugcrowd | 2 |
| 16 | [Hypixel Studios Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/hypixel-studios-mbb-og) | **25,000 USD** | Bugcrowd | 10 |
| 17 | [Kiteworks](https://bugcrowd.com/engagements/kiteworks-public) | **25,000 USD** | Bugcrowd | 1 |
| 18 | [Pinterest](https://bugcrowd.com/engagements/pinterest) | **25,000 USD** | Bugcrowd | 13 |
| 19 | [Chime Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/chime) | **20,000 USD** | Bugcrowd | 19 |
| 20 | [FIS](https://bugcrowd.com/engagements/fis) | **20,000 USD** | Bugcrowd | 2 |
| 21 | [SAP Invitational Bug Bounty Program](https://bugcrowd.com/engagements/sap-private-invite) | **20,000 USD** | Bugcrowd | 25 |
| 22 | [Arm](https://www.intigriti.com/programs/arm/arm/detail) | **20,000 USD** | Intigriti | 2 |
| 23 | [Cash App](https://bugcrowd.com/engagements/cashapp) | **18,000 USD** | Bugcrowd | 4 |
| 24 | [Square](https://bugcrowd.com/engagements/square) | **18,000 USD** | Bugcrowd | 8 |
| 25 | [Bitdefender](https://bugcrowd.com/engagements/bitdefender) | **15,000 USD** | Bugcrowd | 5 |
| 26 | [Bitpanda Ongoing Bug Bounty](https://bugcrowd.com/engagements/bitpanda-og-bb) | **15,000 USD** | Bugcrowd | 10 |
| 27 | [Bitso Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/bitso-mbb-og) | **15,000 USD** | Bugcrowd | 8 |
| 28 | [Canva](https://bugcrowd.com/engagements/canva) | **15,000 USD** | Bugcrowd | 18 |
| 29 | [eToro Managed Bug Bounty Engagement](https://bugcrowd.com/engagements/etoro-mbb-og) | **15,000 USD** | Bugcrowd | 8 |
| 30 | [KuCoin Managed Bug Bounty Program](https://bugcrowd.com/engagements/kucoin) | **15,000 USD** | Bugcrowd | 4 |
| 31 | [BMW Group Automotive](https://www.intigriti.com/programs/bmw/bmwgroup-automotive/detail) | **15,000 EUR** | Intigriti | 4 |
| 32 | [Capital.com](https://www.intigriti.com/programs/capitalcom/capitalcom/detail) | **15,000 EUR** | Intigriti | 12 |
| 33 | [Delen Private Bank](https://www.intigriti.com/programs/delenprivatebank/privatebankdelen/detail) | **15,000 EUR** | Intigriti | 19 |
| 34 | [Dropbox Bug Bounty](https://www.intigriti.com/programs/dropbox/dropbox/detail) | **15,000 USD** | Intigriti | 26 |
| 35 | [Yahoo Bug Bounty](https://www.intigriti.com/programs/yahoo/yahoobugbounty/detail) | **15,000 USD** | Intigriti | 36 |
| 36 | [FDJ United (Online Betting and Gaming) - Bug Bounty program](https://yeswehack.com/programs?search=FDJ%20United%20%28Online%20Betting%20and%20Gaming%29%20-%20Bug%20Bounty%20program) | **15,000 USD** | YesWeHack | 33 |
| 37 | [YesWeHack](https://yeswehack.com/programs?search=YesWeHack) | **15,000 USD** | YesWeHack | 4 |
| 38 | [intigriti](https://www.intigriti.com/programs/intigriti/intigriti/detail) | **13,337 EUR** | Intigriti | 5 |
| 39 | [Monzo Public Bug Bounty Program](https://www.intigriti.com/programs/monzobank/monzopublicbugbountyprogram/detail) | **12,500 GBP** | Intigriti | 6 |
| 40 | [OVHcloud](https://yeswehack.com/programs?search=OVHcloud) | **12,500 USD** | YesWeHack | 3 |

Full top-100 in `data/programs-ranked.csv`, sorted by `payout`.

**Reading this table:** the top of the list is web3 and a handful of telco/automotive giants. High ceilings correlate with *narrow* scope and mature internal security teams. These are the hardest programs in existence and are the wrong place to start.

---

## 2. Most responsive programs on HackerOne

> **Data Limitation Caveat**: Payout data and triage-responsiveness data come from DISJOINT platform sets. HackerOne exposes responsiveness (443 programs) but zero payout figures in this dataset. Bugcrowd, Intigriti, and YesWeHack expose payouts but zero responsiveness figures. The intersection is **ZERO** programs. Therefore, 'pays well AND triages fast' is NOT computable from this dataset. Furthermore, triage times are published by HackerOne in **HOURS** (e.g. 1,543.0 hours = 64.3 days, not 1,543 days).

| Program | Response efficiency | Bounty-eligible assets | Total in-scope | Avg. resolve (hours) | Avg. resolve (days) | Avg. bounty (hours) |
|---|---|---|---|---|---|---|
| [inDrive](https://hackerone.com/indrive) | **100%** | 174 | 174 | 1587.0 | 66.1 | 165.0 |
| [Eternal](https://hackerone.com/eternal) | **100%** | 32 | 34 | 158.0 | 6.6 | 5.0 |
| [Airbnb](https://hackerone.com/airbnb) | **100%** | 27 | 27 | 890.0 | 37.1 | 141.0 |
| [HackerOne](https://hackerone.com/security) | **100%** | 25 | 26 | 175.0 | 7.3 | 1574.0 |
| [Crypto.com](https://hackerone.com/crypto) | **100%** | 24 | 24 | — | — | 121.0 |
| [8x8](https://hackerone.com/8x8-bounty) | **100%** | 20 | 117 | 562.0 | 23.4 | 29.0 |
| [Crowdstrike](https://hackerone.com/crowdstrike) | **100%** | 20 | 20 | — | — | 21.0 |
| [Bykea](https://hackerone.com/bykea) | **100%** | 16 | 16 | — | — | 21.0 |
| [Krisp](https://hackerone.com/krisp) | **100%** | 12 | 15 | 3405.0 | 141.9 | 37.0 |
| [hostinger](https://hackerone.com/hostinger) | **100%** | 12 | 12 | 753.0 | 31.4 | 105.0 |
| [1win](https://hackerone.com/1win_com) | **100%** | 11 | 11 | 1017.0 | 42.4 | 361.0 |
| [Trendyol](https://hackerone.com/trendyol) | **100%** | 11 | 11 | 781.0 | 32.5 | 102.0 |
| [Semrush](https://hackerone.com/semrush) | **100%** | 10 | 14 | 856.0 | 35.7 | 160.0 |
| [Chia Network](https://hackerone.com/chia_network) | **100%** | 9 | 9 | — | — | 354.0 |
| [Matomo](https://hackerone.com/matomo) | **100%** | 9 | 11 | 222.0 | 9.2 | 245.0 |
| [Enjin](https://hackerone.com/enjin) | **100%** | 5 | 6 | — | — | 168.0 |
| [Brave Software](https://hackerone.com/brave) | **100%** | 5 | 5 | — | — | 96.0 |
| [Inditex](https://hackerone.com/inditex) | **100%** | 4 | 4 | — | — | 110.0 |
| [Mergify](https://hackerone.com/mergify) | **100%** | 2 | 2 | 207.0 | 8.6 | 59.0 |
| [ALSCO](https://hackerone.com/alsco) | **100%** | 2 | 2 | — | — | — |
| [Remitly](https://hackerone.com/remitly) | **99%** | 72 | 72 | 3161.0 | 131.7 | 3571.0 |
| [Goldman Sachs](https://hackerone.com/goldmansachs) | **99%** | 38 | 39 | 3756.0 | 156.5 | 193.0 |
| [Slack](https://hackerone.com/slack) | **99%** | 19 | 19 | — | — | 128.0 |
| [Faraday, Inc.](https://hackerone.com/faraday_inc) | **99%** | 12 | 12 | 68.0 | 2.8 | 66.0 |
| [Scopely](https://hackerone.com/scopely) | **99%** | 12 | 24 | 1779.0 | 74.1 | 2107.0 |
| [KOHO](https://hackerone.com/koho) | **99%** | 11 | 11 | 3925.0 | 163.5 | 18.0 |
| [OKG](https://hackerone.com/okg) | **99%** | 10 | 10 | — | — | 546.0 |
| [PortSwigger Web Security](https://hackerone.com/portswigger) | **99%** | 10 | 10 | — | — | 530.0 |
| [Hyatt Hotels](https://hackerone.com/hyatt) | **98%** | 60 | 60 | 2318.0 | 96.6 | 114.0 |
| [Marriott Bug Bounty Program](https://hackerone.com/marriott) | **98%** | 56 | 59 | 818.0 | 34.1 | 277.0 |
| [Vimeo](https://hackerone.com/vimeo) | **98%** | 30 | 30 | 5032.0 | 209.7 | 36.0 |
| [MoonPay](https://hackerone.com/moonpay) | **98%** | 21 | 21 | 15.0 | 0.6 | 90.0 |
| [Early Warning](https://hackerone.com/early_warning) | **98%** | 17 | 17 | 1736.0 | 72.3 | 50.0 |
| [Deriv.com](https://hackerone.com/deriv) | **98%** | 15 | 18 | 72.0 | 3.0 | 95.0 |
| [Vodafone Oman](https://hackerone.com/vodafone_oman) | **98%** | 7 | 7 | 171.0 | 7.1 | 10.0 |
| [PornBox](https://hackerone.com/pornbox) | **98%** | 4 | 4 | 235.0 | 9.8 | 164.0 |
| [Exodus](https://hackerone.com/exodus) | **97%** | 27 | 28 | 93.0 | 3.9 | 367.0 |
| [FanDuel](https://hackerone.com/fanduel) | **97%** | 19 | 19 | — | — | 202.0 |
| [Basecamp](https://hackerone.com/basecamp) | **97%** | 13 | 17 | 11116.0 | 463.2 | 206.0 |
| [Banco Plata](https://hackerone.com/banco_plata) | **97%** | 7 | 7 | 5938.0 | 247.4 | 627.0 |
| [HYPR](https://hackerone.com/hypr-corp) | **97%** | 6 | 6 | 552.0 | 23.0 | 565.0 |
| [Stripchat](https://hackerone.com/stripchat) | **97%** | 2 | 2 | — | — | 247.0 |
| [Booking.com](https://hackerone.com/bookingcom) | **96%** | 49 | 49 | 1573.0 | 65.5 | 775.0 |

**Reading this table:** this is where sustained income lives. Sort `data/programs-ranked.csv` by `resp_eff` desc, filter `offers=True`, and re-run monthly.

---

## 3. Largest attack surface (best for learning and reputation-building)

These programs put thousands of assets in scope — acquisitions, subsidiaries, partner portals and forgotten infrastructure. Most are disclosure-only (unpaid), which makes them ideal for your first 50 reports and terrible for income.

| Program | In-scope assets | Paid | Platform |
|---|---|---|---|
| [Fiserv](https://hackerone.com/fiserv) | **10,923** | no | HackerOne |
| [CBRE](https://hackerone.com/cbre) | **8,691** | no | HackerOne |
| [Clarivate](https://hackerone.com/clarivate) | **5,026** | no | HackerOne |
| [John Deere](https://hackerone.com/john-deere) | **2,050** | no | HackerOne |
| [ION Group](https://hackerone.com/ion) | **1,444** | no | HackerOne |
| [DIB-VDP](https://hackerone.com/dib-vdp) | **1,094** | no | HackerOne |
| [ABB Information Systems Ltd](https://hackerone.com/abb) | **1,063** | no | HackerOne |
| [AWS VDP](https://hackerone.com/aws_vdp) | **554** | no | HackerOne |
| [MTN Group](https://hackerone.com/mtn_group) | **498** | no | HackerOne |
| [Essity](https://hackerone.com/essity) | **480** | no | HackerOne |
| [Esteé  Lauder](https://hackerone.com/estee-lauder) | **471** | no | HackerOne |
| [NBA Public Bug Bounty](https://hackerone.com/nba-public) | **460** | yes | HackerOne |
| [Ferrero](https://hackerone.com/ferrero) | **416** | no | HackerOne |
| [Mondelēz International](https://hackerone.com/mondelez) | **371** | no | HackerOne |
| [Aegean Airlines Vulnerability Disclosure](https://hackerone.com/aegean_airlines_vdp) | **292** | no | HackerOne |
| [Equifax-vdp](https://hackerone.com/equifax) | **283** | no | HackerOne |
| [Daimler Truck](https://hackerone.com/daimler_truck) | **272** | no | HackerOne |
| [Henkel](https://hackerone.com/henkel_vdp) | **266** | no | HackerOne |
| [Aon](https://hackerone.com/aon) | **257** | no | HackerOne |
| [PepsiCo VDP](https://hackerone.com/pepsico_vdp) | **227** | no | HackerOne |
| [HPE VDP](https://hackerone.com/hpe_vdp) | **207** | no | HackerOne |
| [MOD Supply Chain VDP](https://hackerone.com/mod_supply_chain_vdp) | **185** | no | HackerOne |
| [Alshaya](https://hackerone.com/alshaya) | **184** | no | HackerOne |
| [inDrive](https://hackerone.com/indrive) | **174** | yes | HackerOne |
| [Optus Managed Bug Bounty](https://bugcrowd.com/engagements/optus-mbb-og) | **168** | no | Bugcrowd |
| [Visa](https://hackerone.com/visa) | **168** | yes | HackerOne |
| [TransUnion LLC](https://hackerone.com/transunion) | **154** | no | HackerOne |
| [Itaú Unibanco](https://hackerone.com/itau_unibanco) | **137** | no | HackerOne |
| [Allegion](https://hackerone.com/allegion) | **135** | no | HackerOne |
| [OPPO](https://hackerone.com/oppo_bbp) | **133** | yes | HackerOne |
| [Watsons](https://www.intigriti.com/programs/aswatson/watsons/detail) | **123** | yes | Intigriti |
| [Amazon Vulnerability Research Program](https://hackerone.com/amazonvrp) | **121** | yes | HackerOne |
| [Atlassian-Built Apps](https://bugcrowd.com/engagements/atlassianapps) | **119** | no | Bugcrowd |
| [8x8](https://hackerone.com/8x8-bounty) | **117** | yes | HackerOne |
| [Mars](https://hackerone.com/mars) | **112** | no | HackerOne |

---

## 4. Vendor-operated programs (bypass the platforms entirely)

The biggest tech vendors run their own reward programs with their own rules, queues and payout
tables. These are indexed in `by-category/02-enterprise-programs-top500.md` (375 links):

| Vendor | Entry point |
|---|---|
| Google / Alphabet | [bughunters.google.com](https://bughunters.google.com/) — covers Google, Android, Chrome, Cloud, Firebase, Abseil, Angular, Dart, Flutter, Go, Fuchsia, Kubernetes |
| Microsoft | [msrc.microsoft.com](https://msrc.microsoft.com/) — Windows, Azure, Office, .NET, Dynamics, Edge, Xbox, Hyper-V |
| Apple | [security.apple.com/bounty](https://security.apple.com/bounty/) — published reward tables for both devices and services |
| Meta | [bugbounty.meta.com](https://bugbounty.meta.com/) — [scope & reward tiers](https://bugbounty.meta.com/scope/) |
| GitHub | [securitylab.github.com](https://securitylab.github.com/) + HackerOne |
| Tesla | [tesla.com/support/vulnerability-response](https://www.tesla.com/support/vulnerability-response) |
| Intel | [intel.com/.../security-center](https://www.intel.com/content/www/us/en/security-center/default.html) |
| Cisco | [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html) |
| Oracle | [Security Testing Policy](https://www.oracle.com/corporate/security-practices/testing/faq/) + [vulnerability disclosure](https://www.oracle.com/corporate/security-practices/assurance/vulnerability/disclosure/) — **no open bounty program**; disclosure only |
| Samsung | [security.samsungmobile.com](https://security.samsungmobile.com/rewardsProgram.smsb) |
| Qualcomm | [qualcomm.com/company/product-security](https://www.qualcomm.com/company/product-security) |
| NVIDIA | [nvidia.com/en-us/security](https://www.nvidia.com/en-us/security/) |
| IBM | [ibm.com/.../bounty](https://www.ibm.com/security/secure-engineering/bounty.html) |
| Salesforce | [security.salesforce.com](https://security.salesforce.com/) |
| AWS | [aws.amazon.com/security/vulnerability-reporting](https://aws.amazon.com/security/vulnerability-reporting/) |

**ICS / OT / medical device** vendors disclose through CISA rather than a bounty platform —
see [CISA ICS advisories](https://www.cisa.gov/ics-advisories) and
[Siemens CERT portal](https://cert-portal.siemens.com/).

---

## 5. Web3 / smart-contract programs (highest ceilings, highest skill floor)

[Immunefi](https://immunefi.com/explore/) hosts the largest payouts in the industry — OpenSea's
$3M ceiling comes from the Bugcrowd dataset, but Immunefi regularly lists $1M–$10M rewards for
smart-contract and chain-level findings. The skill set is almost disjoint from web hacking
(Solidity/EVM, DeFi composability, oracle manipulation, bridge logic). Enter only if you
already have that background — but if you do, the expected value per hour beats web.

---

## 6. How to use this file with Antigravity

`by-category/02-enterprise-programs-top500.md` is packaged as Antigravity rule files
`11-enterprise-programs-top500-part{1,2}.md` with a `model_decision` trigger, so the agent pulls
in the enterprise program list only when a task involves researching a specific company's
security posture. `data/programs-ranked.csv` stays outside the rules budget for programmatic
queries.
