# Vulnerability Class Reference & Payloads

> Per-vulnerability technique references, payload collections, and deep-dive docs (SQLi, XSS, SSRF, IDOR, deserialization, SSTI, race conditions).
>
> **1521 links.** `live_verified` = HTTP 200 confirmed at harvest time; others returned an anti-bot 403/429 (usually still valid) or 5xx.

| # | Resource | URL | Verified | Source |
|---|---|---|---|---|
| 1 | HackTricks | <https://book.hacktricks.wiki/en> | ✓ | CURATED |
| 2 | HackTricks - methodology | <https://book.hacktricks.wiki/en/generic-methodologies-and-resources/index.html> | ✓ | CURATED |
| 3 | Tom H (hacktricks) writeups | <https://book.hacktricks.wiki/en/real-world-apps/index.html> | ✓ | CURATED |
| 4 | Bug Bounty Hunting methodology (bugbountyguide.com) | <https://bugbountyguide.com> | ✓ | CURATED |
| 5 | Google Cloud Security Bulletins | <https://cloud.google.com/support/bulletins> | ✓ | CURATED |
| 6 | HackTricks Cloud | <https://cloud.hacktricks.wiki/en> | ✓ | CURATED |
| 7 | Stanford CS253 Web Security (free lectures) | <https://cs253.stanford.edu> | ✓ | CURATED |
| 8 | CTF Wiki (comprehensive) | <https://ctf-wiki.org/en> | ✓ | CURATED |
| 9 | ProjectDiscovery docs | <https://docs.projectdiscovery.io> | ✓ | CURATED |
| 10 | Nuclei template docs | <https://docs.projectdiscovery.io/templates/introduction> | ✓ | CURATED |
| 11 | nuclei + templates workflow | <https://docs.projectdiscovery.io/tools/nuclei/overview> | ✓ | CURATED |
| 12 | GTFOBins (unix binary exploitation) | <https://gtfobins.github.io> | ✓ | CURATED |
| 13 | HTML5 Security Cheatsheet | <https://html5sec.org> | ✓ | CURATED |
| 14 | IntelTechniques | <https://inteltechniques.com> | ✓ | CURATED |
| 15 | Detectify Labs (research articles) | <https://labs.detectify.com> | ✓ | CURATED |
| 16 | LOLBAS (Living Off The Land Binaries and Scripts) | <https://lolbas-project.github.io> | ✓ | CURATED |
| 17 | OSINT Framework | <https://osintframework.com> | ✓ | CURATED |
| 18 | PortSwigger BApp store (extensions) | <https://portswigger.net/bappstore> | ✓ | CURATED |
| 19 | PortSwigger Burp Suite | <https://portswigger.net/burp> | ✓ | CURATED |
| 20 | Burp Suite Community/Pro | <https://portswigger.net/burp/communitydownload> | ✓ | CURATED |
| 21 | PortSwigger Burp Suite Documentation | <https://portswigger.net/burp/documentation> | ✓ | CURATED |
| 22 | Burp Collaborator | <https://portswigger.net/burp/documentation/collaborator> | ✓ | CURATED |
| 23 | PortSwigger Research (exploit techniques) | <https://portswigger.net/research> | ✓ | CURATED |
| 24 | PortSwigger Web Security Academy (free) | <https://portswigger.net/web-security> | ✓ | CURATED |
| 25 | PortSwigger Web Security Academy labs | <https://portswigger.net/web-security/all-labs> | ✓ | CURATED |
| 26 | Burp Suite Certified Practitioner | <https://portswigger.net/web-security/certification> | ✓ | CURATED |
| 27 | XSS cheat sheet (PortSwigger) | <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet> | ✓ | CURATED |
| 28 | ASU CSE466 / SEED Labs | <https://seedsecuritylabs.org> | ✓ | CURATED |
| 29 | SEED Labs | <https://seedsecuritylabs.org/labs.html> | ✓ | CURATED |
| 30 | PayloadsAllTheThings | <https://swisskyrepo.github.io/PayloadsAllTheThings> | ✓ | CURATED |
| 31 | Threat Modeling book site | <https://threatmodelingbook.com> | ✓ | CURATED |
| 32 | OWASP Zed Attack Proxy (ZAP) | <https://zaproxy.org> | ✓ | CURATED |
| 33 | OWASP ZAP docs | <https://zaproxy.org/docs> | ✓ | CURATED |
| 34 | James Kettle | <http://albinowax.skeletonscribe.net> | ✓ | awesome-web-security |
| 35 | Inside Windows Debugging | <http://amzn.to/2iqFTxf> | ✓ | awesome reverse-engineering |
| 36 | Practical Reverse Engineering | <http://amzn.to/2iusXRW> | ✓ | awesome reverse-engineering |
| 37 | Malware Analyst's Cookbook | <http://amzn.to/2iWPJDd> | ✓ | awesome reverse-engineering |
| 38 | The Rootkit Arsenal | <http://amzn.to/2jlgioK> | ✓ | awesome reverse-engineering |
| 39 | Practical Malware Analysis | <http://amzn.to/2jljYqE> | ✓ | awesome reverse-engineering |
| 40 | Gray Hat Hacking | <http://amzn.to/2jllIAi> | ✓ | awesome reverse-engineering |
| 41 | Reversing: Secrets of Reverse Engineering | <http://amzn.to/2jlnBwX> | ✓ | awesome reverse-engineering |
| 42 | Windows Internals Part 1 | <http://amzn.to/2jlo9mA> | ✓ | awesome reverse-engineering |
| 43 | The Art of Assembly Language | <http://amzn.to/2jlxTNp> | ✓ | awesome reverse-engineering |
| 44 | The Art of Memory Forensics | <http://amzn.to/2jMJQs0> | ✓ | awesome reverse-engineering |
| 45 | Part 2 | <http://amzn.to/2jMLCth> | ✓ | awesome reverse-engineering |
| 46 | The Antivirus Hacker's Handbook | <http://amzn.to/2jn9G99> | ✓ | awesome reverse-engineering |
| 47 | Hacking: The Art of Exploitation | <http://amzn.to/2jnkV19> | ✓ | awesome reverse-engineering |
| 48 | The IDA Pro Book | <http://amzn.to/2jTicOg> | ✓ | awesome reverse-engineering |
| 49 | Cerbero Profiler | <http://cerbero-blog.com/?p=1311> | ✓ | awesome reverse-engineering |
| 50 | Reverse Engineering Challenges | <http://challenges.re> | ✓ | awesome reverse-engineering |
| 51 | Daniel LeCheminant | <http://danlec.com> | ✓ | awesome-web-security |
| 52 | XSS via a spoofed React element | <http://danlec.com/blog/xss-via-a-spoofed-react-element> | ✓ | awesome-web-security |
| 53 | Ole Tools | <http://decalage.info/python/oletools> | ✓ | awesome reverse-engineering |
| 54 | HackDig | <http://en.hackdig.com> | ✓ | awesome-web-security |
| 55 | Flare-on Challenges | <http://flare-on.com> | ✓ | awesome reverse-engineering |
| 56 | FLAWS | <http://flaws.cloud> | ✓ | awesome-web-security |
| 57 | Dr. Fu's Malware Analysis | <http://fumalwareanalysis.blogspot.sg/p/malware-analysis-tutorials-reverse.html> | ✓ | awesome reverse-engineering |
| 58 | — | <http://help.365cyd.com/cyd-error-help.html?code=403> | ✓ | Awesome-WAF |
| 59 | Hex Workshop | <http://hexworkshop.com> | ✓ | awesome reverse-engineering |
| 60 | Hiew | <http://hiew.ru> | ✓ | awesome reverse-engineering |
| 61 | HPing3 | <http://hping.org> | ✓ | Awesome-WAF |
| 62 | Reference | <http://html5sec.org> | ✓ | Awesome-WAF |
| 63 | @hyp3rlinx | <http://hyp3rlinx.altervista.org> | ✓ | Awesome-WAF |
| 64 | iNetSim | <http://inetsim.org> | ✓ | awesome reverse-engineering |
| 65 | IP History | <http://iphistory.ch/en> | ✓ | Awesome-WAF |
| 66 | JSFuck | <http://jsfuck.com> | ✓ | Awesome-WAF |
| 67 | Top Hacking Books | <http://kalitut.com/2016/12/best-ethical-hacking-books.html> | ✓ | awesome reverse-engineering |
| 68 | Top Java Books | <http://kalitut.com/2017/01/Best-Java-Programming-Books.html> | ✓ | awesome reverse-engineering |
| 69 | Top Reverse Engineering Books | <http://kalitut.com/2017/01/Best-reverse-engineering-books.html> | ✓ | awesome reverse-engineering |
| 70 | Top 5 books Programming Books | <http://kalitut.com/2017/01/Top-Programming-Books.html> | ✓ | awesome reverse-engineering |
| 71 | labs.detectify.com | <http://labs.detectify.com> | ✓ | awesome-bug-bounty |
| 72 | — | <http://litespeedtech.com/error-page> | ✓ | Awesome-WAF |
| 73 | lldb | <http://lldb.llvm.org> | ✓ | awesome reverse-engineering |
| 74 | Malshare | <http://malshare.com> | ✓ | awesome reverse-engineering |
| 75 | dtrace recipes | <http://mfukar.github.io/2014/03/19/dtrace.html> | ✓ | awesome reverse-engineering |
| 76 | Mobius Resources | <http://msreverseengineering.com/research> | ✓ | awesome reverse-engineering |
| 77 | — | <http://newdefend.com/feedback/misinformation> | ✓ | Awesome-WAF |
| 78 | SmartSniff | <http://nirsoft.net/utils/smsniff.html> | ✓ | awesome reverse-engineering |
| 79 | Detect It Easy | <http://ntinfo.biz> | ✓ | awesome reverse-engineering |
| 80 | OllyDbg v2.01 | <http://ollydbg.de/version2.html> | ✓ | awesome reverse-engineering |
| 81 | OSINT Framework | <http://osintframework.com> | ✓ | awesome-pentest |
| 82 | burpsuite | <http://portswigger.net/burp> | ✓ | ctf-tools |
| 83 | Rafay Bloch | <http://rafaybaloch.com> | ✓ | Awesome-WAF |
| 84 | Using IDAPython to Make your Life Easier | <http://researchcenter.paloaltonetworks.com/tag/idapython> | ✓ | awesome reverse-engineering |
| 85 | API Monitor | <http://rohitab.com/apimonitor> | ✓ | awesome reverse-engineering |
| 86 | — | <http://schemas.xmlsoap.org/soap/envelope> | ✓ | Awesome-WAF |
| 87 | 010 Editor | <http://sweetscape.com/010editor> | ✓ | awesome reverse-engineering |
| 88 | — | <http://tempuri.org> | ✓ | Awesome-WAF |
| 89 | JJEncode | <http://utf-8.jp/public/jjencode.html> | ✓ | Awesome-WAF |
| 90 | University of Amsterdam | <http://uva.nl> | ✓ | Awesome-WAF |
| 91 | Virusshare.com | <http://virusshare.com> | ✓ | awesome reverse-engineering |
| 92 | vxvault | <http://vxvault.net> | ✓ | awesome reverse-engineering |
| 93 | PeStudio | <http://winitor.com> | ✓ | awesome reverse-engineering |
| 94 | LordPE | <http://woodmann.com/collaborative/tools/images/Bin_LordPE_2010-6-29_3.9_LordPE_1.41_Deluxe_b.zip> | ✓ | awesome reverse-engineering |
| 95 | TiGa's Video Tutorials | <http://woodmann.com/TiGa> | ✓ | awesome reverse-engineering |
| 96 | xorpd Advanced Assembly Exercises | <http://xorpd.net/pages/xchg_rax/snip_00.html> | ✓ | awesome reverse-engineering |
| 97 | XSS Challenges | <http://xss-quiz.int21h.jp> | ✓ | awesome-web-security |
| 98 | Yara docs | <http://yara.readthedocs.org/en/v3.4.0/writingrules.html> | ✓ | awesome reverse-engineering |
| 99 | Altus iX Developer XAML Deserialization RCE | <https://0day-rubbish.com/blog/altus-ix-developer-xaml-rce> | ✓ | awesome-web-security |
| 100 | 0Day Inject0r DB | <https://0day.today> | ✓ | Awesome-WAF |
| 101 | Bypassing Web-Application Firewalls by abusing SSL/TLS | <https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html> | ✓ | Awesome-WAF |
| 102 | Gwen | <https://10degres.net> | ✓ | awesome-web-security |
| 103 | AWS takeover through SSRF in JavaScript | <https://10degres.net/aws-takeover-through-ssrf-in-javascript> | ✓ | awesome-web-security |
| 104 | The 200 That Proved Nothing | <https://aivist.dev/the-200-that-proved-nothing> | ✓ | awesome-web-security |
| 105 | alert(1) to win | <https://alf.nu/alert1> | ✓ | awesome-web-security |
| 106 | DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE | <https://ambionics.io/blog/drupal-services-module-rce> | ✓ | awesome-web-security |
| 107 | channel, #testing-guide | <https://app.slack.com/client/T04T40NHX/CJ2QDHLRJ> | ✓ | OWASP/wstg (README.md) |
| 108 | APTIVE | <https://aptive.co.uk> | ✓ | awesome-web-security |
| 109 | BAIMAOHUI | <https://baimaohui.net> | ✓ | awesome-web-security |
| 110 | beefproject | <https://beefproject.com> | ✓ | awesome-web-security |
| 111 | — | <https://bekchy.com/report> | ✓ | Awesome-WAF |
| 112 | Belfer Center for Science and International Affairs | <https://belfercenter.org> | ✓ | awesome-web-security |
| 113 | CFR | <https://benf.org/other/cfr> | ✓ | awesome-web-security |
| 114 | The Magic of Learning | <https://bitvijays.github.io> | ✓ | awesome-web-security |
| 115 | 0Day Labs | <https://blog.0daylabs.com> | ✓ | awesome-web-security |
| 116 | Michał Bentkowski | <https://blog.bentkowski.info> | ✓ | awesome-web-security |
| 117 | Setting arbitrary request headers in Chromium via CRLF injection | <https://blog.bentkowski.info/2018/06/setting-arbitrary-request-headers-in.html> | ✓ | awesome-web-security |
| 118 | Sergey Bobrov | <https://blog.blackfan.ru> | ✓ | awesome-web-security |
| 119 | HQL for pentesters | <https://blog.h3xstream.com/2014/02/hql-for-pentesters.html> | ✓ | awesome-web-security |
| 120 | Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-... | <https://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html> | ✓ | awesome-web-security |
| 121 | Forcing XXE Reflection through Server Error Messages | <https://blog.netspi.com/forcing-xxe-reflection-server-error-messages> | ✓ | awesome-web-security |
| 122 | Hacking with JSP Shells | <https://blog.netspi.com/hacking-with-jsp-shells> | ✓ | awesome-web-security |
| 123 | How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE! | <https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on> | ✓ | awesome-web-security |
| 124 | RET2 SYSTEMS, INC | <https://blog.ret2.io> | ✓ | awesome-web-security |
| 125 | A Methodical Approach to Browser Exploitation | <https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development> | ✓ | awesome-web-security |
| 126 | Remote Code Execution on a Facebook server | <https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server> | ✓ | awesome-web-security |
| 127 | Gareth Heyes | <https://blogger.com/profile/10856178524811553475> | ✓ | awesome-web-security |
| 128 | SecuriTeam Secure Disclosure (SSD) | <https://blogs.securiteam.com> | ✓ | awesome-web-security |
| 129 | SSD Advisory – Chrome Turbofan Remote Code Execution | <https://blogs.securiteam.com/index.php/archives/3379> | ✓ | awesome-web-security |
| 130 | HackTricks Values & FAQ | <https://book.hacktricks.wiki/en/welcome/hacktricks-values-and-faq.html> | ✓ | HackTricks-wiki/hacktricks-cloud (README.md) |
| 131 | GitHub Enterprise Remote Code Execution | <https://bounty.github.com/researchers/iblue.html> | ✓ | awesome-web-security |
| 132 | Broken Browser | <https://brokenbrowser.com> | ✓ | awesome-web-security |
| 133 | BSides Manchester | <https://bsidesmcr.org.uk> | ✓ | Awesome-WAF |
| 134 | grayhatwarfare | <https://buckets.grayhatwarfare.com> | ✓ | awesome-web-security |
| 135 | BunkerWeb | <https://bunkerweb.io> | ✓ | awesome-web-security |
| 136 | chaitin | <https://chaitin.com> | ✓ | awesome-web-security |
| 137 | Charles Proxy | <https://charlesproxy.com> | ✓ | awesome-web-security |
| 138 | Claude Code | <https://claude.com/claude-code> | ✓ | awesome-web-security |
| 139 | — | <https://cloudrity.com.vn> | ✓ | Awesome-WAF |
| 140 | — | <https://cloudrity.com.vn/customer> | ✓ | Awesome-WAF |
| 141 | CODE WHITE | <https://code-white.com> | ✓ | awesome-web-security |
| 142 | OWASP CRS team | <https://coreruleset.org> | ✓ | Awesome-WAF |
| 143 | @cossacklabs | <https://cossacklabs.com> | ✓ | awesome-web-security |
| 144 | CrowdSec | <https://crowdsec.net> | ✓ | awesome-web-security |
| 145 | J.M Porup | <https://csoonline.com/author/J.M.-Porup> | ✓ | awesome-web-security |
| 146 | Laravel CSP Generator | <https://csp-generator.shakiltech.com> | ✓ | awesome-web-security |
| 147 | Csper | <https://csper.io> | ✓ | awesome-web-security |
| 148 | csp evaluator | <https://csper.io/evaluator> | ✓ | awesome-web-security |
| 149 | Cuckoo | <https://cuckoosandbox.org> | ✓ | awesome reverse-engineering |
| 150 | Cure53 | <https://cure53.de> | ✓ | awesome-web-security |
| 151 | cure53.de/m | <https://cure53.de/m> | ✓ | awesome-web-security |
| 152 | Scrutiny | <https://datarift.blogspot.tw> | ✓ | awesome-web-security |
| 153 | Why Facebook's api starts with a for loop | <https://dev.to/antogarand/why-facebooks-api-starts-with-a-for-loop-1eob> | ✓ | awesome-web-security |
| 154 | User Guide | <https://developer.apple.com/library/watchos/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/index.html> | ✓ | awesome reverse-engineering |
| 155 | XCode Instruments | <https://developer.apple.com/xcode/download> | ✓ | awesome reverse-engineering |
| 156 | Diary of a reverse-engineer | <https://doar-e.github.io> | ✓ | awesome-web-security |
| 157 | CVE-2017-2446 or JSC::JSGlobalObject::isHavingABadTime. | <https://doar-e.github.io/blog/2018/07/14/cve-2017-2446-or-jscjsglobalobjectishavingabadtime> | ✓ | awesome-web-security |
| 158 | How do we Stop Spilling the Beans Across Origins? | <https://docs.google.com/document/d/1cbL-X0kV_tQ5rL8XJ3lXkV-j0pt_CfTu5ZSzYrncPDc> | ✓ | awesome-web-security |
| 159 | SSRF bible. Cheatsheet | <https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit> | ✓ | awesome-web-security |
| 160 | The Bug Hunters Methodology v2.1 | <https://docs.google.com/presentation/d/1VpRT8dFyTaFpQa9jhehtmGaC7TqQniMSYbUdlHN6VrY/edit?usp=sharing> | ✓ | awesome-web-security |
| 161 | TCPView | <https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview> | ✓ | awesome reverse-engineering |
| 162 | Доктор Веб | <https://drweb.ru> | ✓ | awesome-web-security |
| 163 | ElevenPaths | <https://elevenpaths.com/index.html> | ✓ | awesome-web-security |
| 164 | epi | <https://epi052.gitlab.io/notes-to-self> | ✓ | awesome-web-security |
| 165 | How to Hunt Bugs in SAML; a Methodology - Part I | <https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology> | ✓ | awesome-web-security |
| 166 | How to Hunt Bugs in SAML; a Methodology - Part II | <https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two> | ✓ | awesome-web-security |
| 167 | How to Hunt Bugs in SAML; a Methodology - Part III | <https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three> | ✓ | awesome-web-security |
| 168 | C.XSS Guide | <https://excess-xss.com> | ✓ | awesome-web-security |
| 169 | IE11 Information disclosure - local file detection | <https://facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater> | ✓ | awesome-web-security |
| 170 | Yara First Presentation | <https://first.org/resources/papers/conference2014/first_2014_-_schuster-_andreas_-_yara_basic_and_advanced_20140619.pdf> | ✓ | awesome reverse-engineering |
| 171 | FOFA | <https://fofa.so/?locale=en> | ✓ | awesome-web-security |
| 172 | JPEXS Flash Decompiler | <https://free-decompiler.com/flash> | ✓ | awesome reverse-engineering |
| 173 | George Mauer | <https://georgemauer.net> | ✓ | awesome-web-security |
| 174 | The Absurdly Underestimated Dangers of CSV Injection | <https://georgemauer.net/2017/10/07/csv-injection.html> | ✓ | awesome-web-security |
| 175 | Radare2 Book | <https://gitbook.com/book/radare/radare2book/details> | ✓ | awesome reverse-engineering |
| 176 | GitHub's CSP journey | <https://github.blog/2016-04-12-githubs-csp-journey> | ✓ | awesome-web-security |
| 177 | GitHub's post-CSP journey | <https://github.blog/2017-01-19-githubs-post-csp-journey> | ✓ | awesome-web-security |
| 178 | Google Search | <https://google.com> | ✓ | awesome-web-security |
| 179 | Automating local DTD discovery for XXE exploitation | <https://gosecure.ai/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation> | ✓ | awesome-web-security |
| 180 | grayhatwarfare | <https://grayhatwarfare.com> | ✓ | awesome-web-security |
| 181 | Google Group | <https://groups.google.com/a/owasp.org/forum> | ✓ | OWASP/wstg (README.md) |
| 182 | Breaking UC Browser | <https://habr.com/en/company/drweb/blog/452076> | ✓ | awesome-web-security |
| 183 | Hackxor | <https://hackxor.net> | ✓ | awesome-web-security |
| 184 | IDA Plugin Contest | <https://hex-rays.com/contests> | ✓ | awesome reverse-engineering |
| 185 | IDC Functions Doc | <https://hex-rays.com/products/ida/support/idadoc/162.shtml> | ✓ | awesome reverse-engineering |
| 186 | Hudson Rock | <https://hudsonrock.com> | ✓ | awesome-web-security |
| 187 | Hudson Rock | <https://hudsonrock.com/threat-intelligence-cybercrime-tools> | ✓ | awesome-web-security |
| 188 | Imperva | <https://imperva.com> | ✓ | Awesome-WAF |
| 189 | WAF Testing Framework | <https://imperva.com/lg/lgw_trial.asp?pid=483> | ✓ | Awesome-WAF |
| 190 | jameshfisher | <https://jameshfisher.com> | ✓ | awesome-web-security |
| 191 | The inception bar: a new phishing method | <https://jameshfisher.com/2019/04/27/the-inception-bar-a-new-phishing-method> | ✓ | awesome-web-security |
| 192 | bypass Google Cloud Platform WAF | <https://kloudle.com/blog/piercing-the-cloud-armor-the-8kb-bypass-in-google-cloud-platform-waf> | ✓ | Awesome-WAF |
| 193 | CSP: bypassing form-action with reflected XSS | <https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss> | ✓ | awesome-web-security |
| 194 | How we invented the Tesla DOM XSS | <https://labs.detectify.com/2017/07/27/how-we-invented-the-tesla-dom-doom-xss> | ✓ | Awesome-Bugbounty-Writeups |
| 195 | How I exploited ACME TLS-SNI-01 issuing Let's Encrypt SSL-certs for any domain using sh... | <https://labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting> | ✓ | awesome-web-security |
| 196 | leavesongs | <https://leavesongs.com> | ✓ | awesome-web-security |
| 197 | Some Tricks From My Secret Group | <https://leavesongs.com/SHARE/some-tricks-from-my-secret-group.html> | ✓ | awesome-web-security |
| 198 | Daniel Stelter-Gliese | <https://linkedin.com/in/daniel-stelter-gliese-170a70a2> | ✓ | awesome-web-security |
| 199 | — | <https://maintenance.blackbaud.com> | ✓ | Awesome-WAF |
| 200 | Mitsui Bussan Secure Directions, Inc. | <https://mbsd.jp> | ✓ | awesome-web-security |
| 201 | MBSD Technical Whitepaper - A few RPO exploitation techniques | <https://mbsd.jp/Whitepaper/rpo.pdf> | ✓ | awesome-web-security |
| 202 | XML Out-Of-Band Data Retrieval | <https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf> | ✓ | awesome-web-security |
| 203 | HxD | <https://mh-nexus.de/en/hxd> | ✓ | awesome reverse-engineering |
| 204 | Arseniy Sharoglazov | <https://mohemiv.com> | ✓ | awesome-web-security |
| 205 | Evil XML with two encodings | <https://mohemiv.com/all/evil-xml> | ✓ | awesome-web-security |
| 206 | Exploiting XXE with local DTD files | <https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files> | ✓ | awesome-web-security |
| 207 | WinDbg | <https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx> | ✓ | awesome reverse-engineering |
| 208 | Netsparker | <https://netsparker.com> | ✓ | awesome-web-security |
| 209 | NETSPI | <https://netspi.com> | ✓ | awesome-web-security |
| 210 | Some Problems Of URLs | <https://noncombatant.org/2017/11/07/problems-of-urls> | ✓ | awesome-web-security |
| 211 | Chris Palmer | <https://noncombatant.org/about> | ✓ | awesome-web-security |
| 212 | NSFOCUS | <https://nti.nsfocus.com> | ✓ | awesome-web-security |
| 213 | Objective-See Utilities | <https://objective-see.com/products.html> | ✓ | awesome reverse-engineering |
| 214 | Simone Onofri | <https://onofri.org> | ✓ | awesome-web-security |
| 215 | OpenBuckets | <https://openbuckets.io> | ✓ | awesome-web-security |
| 216 | Enguerran Gillier | <https://opnsec.com> | ✓ | awesome-web-security |
| 217 | Stored XSS on Facebook | <https://opnsec.com/2018/03/stored-xss-on-facebook> | ✓ | awesome-web-security |
| 218 | Escape and Evasion Egressing Restricted Networks | <https://optiv.com/blog/escape-and-evasion-egressing-restricted-networks> | ✓ | awesome-web-security |
| 219 | Blog of Osanda | <https://osandamalith.com> | ✓ | awesome-web-security |
| 220 | Bypassing All Protections Using A Whitelist String | <https://osandamalith.com/2019/10/12/bypassing-the-webarx-web-application-firewall-waf> | ✓ | Awesome-WAF |
| 221 | @OWASP | <https://owasp.com> | ✓ | Awesome-WAF |
| 222 | Pastebin | <https://pastebin.com> | ✓ | Awesome-WAF |
| 223 | XSS Bypass | <https://pastebin.com/i8Ans4d4> | ✓ | Awesome-WAF |
| 224 | CRISTIAN CORNEA | <https://pentest-tools.com/blog/author/pentest-cristian> | ✓ | awesome-web-security |
| 225 | How to exploit the DotNetNuke Cookie Deserialization | <https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization> | ✓ | awesome-web-security |
| 226 | peoplefindThor | <https://peoplefindthor.dk> | ✓ | awesome-web-security |
| 227 | — | <https://perimeterx.com/whywasiblocked> | ✓ | Awesome-WAF |
| 228 | GraphQL NoSQL Injection Through JSON Types | <https://petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types> | ✓ | awesome-web-security |
| 229 | Pete | <https://petecorey.com/work> | ✓ | awesome-web-security |
| 230 | XXE | <https://phonexicum.github.io/infosec/xxe.html> | ✓ | awesome-web-security |
| 231 | Phrack Magazine | <https://phrack.org> | ✓ | awesome-web-security |
| 232 | — | <https://policies.accenture.com> | ✓ | Awesome-WAF |
| 233 | PortSwigger Web Security | <https://portswigger.net> | ✓ | awesome-web-security |
| 234 | Bypass WAF BurpSuite Plugin | <https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c> | ✓ | Awesome-WAF |
| 235 | Bypassing Web Cache Poisoning Countermeasures | <https://portswigger.net/blog/bypassing-web-cache-poisoning-countermeasures> | ✓ | awesome-web-security |
| 236 | Evading CSP with DOM-based dangling markup | <https://portswigger.net/blog/evading-csp-with-dom-based-dangling-markup> | ✓ | awesome-web-security |
| 237 | Practical Web Cache Poisoning | <https://portswigger.net/blog/practical-web-cache-poisoning> | ✓ | awesome-web-security |
| 238 | So you want to be a web security researcher? | <https://portswigger.net/blog/so-you-want-to-be-a-web-security-researcher> | ✓ | awesome-web-security |
| 239 | XSS in hiden input fields | <https://portswigger.net/blog/xss-in-hidden-input-fields> | ✓ | Awesome-Bugbounty-Writeups |
| 240 | XSS without parentheses and semi-colons | <https://portswigger.net/blog/xss-without-parentheses-and-semi-colons> | ✓ | awesome-web-security |
| 241 | Burp Suite Mobile Assistant | <https://portswigger.net/burp/documentation/desktop/mobile-testing> | ✓ | MobileApp-Pentest-Cheatsheet |
| 242 | Burp Suite | <https://portswigger.net/burp/download.html> | ✓ | MobileApp-Pentest-Cheatsheet |
| 243 | The Daily Swig - Web security digest | <https://portswigger.net/daily-swig> | ✓ | awesome-web-security |
| 244 | DOM based Angular sandbox escapes | <https://portswigger.net/research/dom-based-angularjs-sandbox-escapes> | ✓ | awesome-web-security |
| 245 | JSON hijacking for the modern web | <https://portswigger.net/research/json-hijacking-for-the-modern-web> | ✓ | awesome-web-security |
| 246 | Turbo Intruder | <https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack> | ✓ | awesome-ctf |
| 247 | XSS without HTML: Client-Side Template Injection with AngularJS | <https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs> | ✓ | awesome-web-security |
| 248 | Portswigger's lab | <https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api> | ✓ | Web-CTF-Cheatsheet |
| 249 | XML external entity (XXE) injection | <https://portswigger.net/web-security/xxe> | ✓ | awesome-web-security |
| 250 | PwnDizzle | <https://pwndizzle.blogspot.jp> | ✓ | awesome-web-security |
| 251 | Brute Forcing Your Facebook Email and Phone Number | <https://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html> | ✓ | awesome-web-security |
| 252 | Qualys | <https://qualys.com> | ✓ | Awesome-WAF |
| 253 | Rafay Baloch | <https://rafaybaloch.com> | ✓ | Awesome-WAF |
| 254 | Rails SQL Injection | <https://rails-sqli.org> | ✓ | awesome-web-security |
| 255 | OSX Crackmes | <https://reverse.put.as/crackmes> | ✓ | awesome reverse-engineering |
| 256 | Rails team | <https://rubyonrails.org> | ✓ | awesome-web-security |
| 257 | s0cket7 | <https://s0cket7.com> | ✓ | awesome-web-security |
| 258 | Stored XSS, and SSRF in Google using the Dataset Publishing Language | <https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html> | ✓ | awesome-web-security |
| 259 | Scapy | <https://scapy.net> | ✓ | Awesome-WAF |
| 260 | XXE in WeChat Pay Sdk ( WeChat leave a backdoor on merchant websites) | <https://seclists.org/fulldisclosure/2018/Jul/3> | ✓ | awesome-web-security |
| 261 | State of TLS on the public web | <https://securemonk.io/insights/state-of-tls> | ✓ | awesome-web-security |
| 262 | SecuriTool | <https://securitool.js.org> | ✓ | awesome-web-security |
| 263 | SELinux Game | <https://selinuxgame.org> | ✓ | awesome-web-security |
| 264 | Hardcoded secrets, unverified tokens, and other common JWT mistakes | <https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes> | ✓ | awesome-web-security |
| 265 | Alexander Klink | <https://shiftordie.de> | ✓ | awesome-web-security |
| 266 | SMTP over XXE − how to send emails using Java's XML parser | <https://shiftordie.de/blog/2017/02/18/smtp-over-xxe> | ✓ | awesome-web-security |
| 267 | Google VRP and Unicorns | <https://sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns> | ✓ | awesome-web-security |
| 268 | Ezequiel Pereira | <https://sites.google.com/site/testsitehacking> | ✓ | awesome-web-security |
| 269 | $7.5k Google services mix-up | <https://sites.google.com/site/testsitehacking/-7-5k-Google-services-mix-up> | ✓ | awesome-web-security |
| 270 | The Cookie Monster in Your Browsers | <https://speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers> | ✓ | awesome-web-security |
| 271 | The world of Site Isolation and compromised renderer | <https://speakerdeck.com/shhnjk/the-world-of-site-isolation-and-compromised-renderer> | ✓ | awesome-web-security |
| 272 | SPLOITUS | <https://sploitus.com> | ✓ | awesome-web-security |
| 273 | sqlchop | <https://sqlchop.chaitin.cn> | ✓ | awesome-web-security |
| 274 | SQL Injection Wiki | <https://sqlwiki.netspi.com> | ✓ | awesome-web-security |
| 275 | Qualys SSL Labs | <https://ssllabs.com> | ✓ | awesome-web-security |
| 276 | Qualys SSL Check | <https://ssllabs.com/ssltest> | ✓ | awesome-web-security |
| 277 | — | <https://status.blackbaud.com> | ✓ | Awesome-WAF |
| 278 | — | <https://sucuri.net/privacy-policy> | ✓ | Awesome-WAF |
| 279 | How To Reverse Engineer A Web Application Firewall Using Regular Expression Reversing | <https://sunnyhoi.com/reverse-engineer-web-application-firewall-using-regular-expression-reversing> | ✓ | Awesome-WAF |
| 280 | XChars.JS | <https://syllab.fr/projets/experiments/xcharsjs/5chars.pipeline.html> | ✓ | Awesome-WAF |
| 281 | HOW TO EXPLOIT LIFERAY CVE-2020-7961 : QUICK JOURNEY TO POC | <https://synacktiv.com/en/publications/how-to-exploit-liferay-cve-2020-7961-quick-journey-to-poc.html> | ✓ | awesome-web-security |
| 282 | HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injec... | <https://synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf> | ✓ | awesome-web-security |
| 283 | XSS Bypass | <https://sysdig.com/blog/fuzzing-and-bypassing-the-aws-waf> | ✓ | Awesome-WAF |
| 284 | Red Team Tales 0x01: From MSSQL to RCE | <https://tarlogic.com/en/blog/red-team-tales-0x01> | ✓ | awesome-web-security |
| 285 | Autoruns | <https://technet.microsoft.com/en-us/sysinternals/bb963902> | ✓ | awesome reverse-engineering |
| 286 | Process Explorer | <https://technet.microsoft.com/en-us/sysinternals/processexplorer> | ✓ | awesome reverse-engineering |
| 287 | Process Monitor | <https://technet.microsoft.com/en-us/sysinternals/processmonitor> | ✓ | awesome reverse-engineering |
| 288 | Jayson | <https://techvomit.net> | ✓ | awesome-web-security |
| 289 | WEB APPLICATION PENETRATION TESTING NOTES | <https://techvomit.net/web-application-penetration-testing-notes> | ✓ | awesome-web-security |
| 290 | Hunting for Web Shells | <https://tenable.com/blog/hunting-for-web-shells> | ✓ | awesome-web-security |
| 291 | Jacob Baines | <https://tenable.com/profile/jacob-baines> | ✓ | awesome-web-security |
| 292 | CVE-2019-1306: ARE YOU MY INDEX? | <https://thezdi.com/blog/2019/10/23/cve-2019-1306-are-you-my-index> | ✓ | awesome-web-security |
| 293 | Trail of Bits | <https://trailofbits.com> | ✓ | awesome-web-security |
| 294 | CTF Field Guide | <https://trailofbits.github.io/ctf> | ✓ | awesome-web-security |
| 295 | this | <https://url-encode-decode.com> | ✓ | Awesome-WAF |
| 296 | VRGSEC | <https://vgrsec.com> | ✓ | awesome-web-security |
| 297 | Unicode Domains are bad and you should feel bad for supporting them | <https://vgrsec.com/post20170219.html> | ✓ | awesome-web-security |
| 298 | Virus Total | <https://virustotal.com> | ✓ | awesome-web-security |
| 299 | VirusTotal domain information | <https://virustotal.com/en/documentation/searching> | ✓ | awesome-web-security |
| 300 | @WAFNinja | <https://waf.ninja> | ✓ | Awesome-WAF |
| 301 | SQL Injection Pocket Reference | <https://websec.ca/kb/sql_injection> | ✓ | awesome-web-security |
| 302 | WCTF2019: Gyotaku The Flag | <https://westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf> | ✓ | awesome-web-security |
| 303 | XSS game | <https://xss-game.appspot.com> | ✓ | awesome-web-security |
| 304 | xsschop | <https://xsschop.chaitin.cn> | ✓ | awesome-web-security |
| 305 | Xudong Zheng | <https://xudongz.com> | ✓ | awesome-web-security |
| 306 | Phishing with Unicode Domains | <https://xudongz.com/blog/2017/idn-phishing> | ✓ | awesome-web-security |
| 307 | zhchbin | <https://zhchbin.github.io> | ✓ | awesome-web-security |
| 308 | Uber XSS via Cookie | <https://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie> | ✓ | awesome-web-security |
| 309 | Didier's PDF Tools | <http://blog.didierstevens.com/programs/pdf-tools> | ~ | awesome reverse-engineering |
| 310 | Bytecode Visualizer | <http://drgarbage.com/bytecode-visualizer> | ~ | awesome reverse-engineering |
| 311 | dtrace | <http://dtrace.org/blogs/brendan/2011/10/10/top-10-dtrace-scripts-for-mac-os-x> | ~ | awesome reverse-engineering |
| 312 | — | <http://host.com/?randomparameter=> | ~ | Awesome-WAF |
| 313 | — | <http://host.com/?vulnparam=> | ~ | Awesome-WAF |
| 314 | — | <http://host.com/?vulnparam=../../../../../etc/passwd&ithemes-sync-request> | ~ | Awesome-WAF |
| 315 | — | <http://host.com/?vulnparam=1%20unionselect%20@@version,2--&ithemes-sync-request> | ~ | Awesome-WAF |
| 316 | — | <http://host.com/test.asp?file=.%./bla.txt> | ~ | Awesome-WAF |
| 317 | objdump | <http://linux.die.net/man/1/objdump> | ~ | awesome reverse-engineering |
| 318 | Dumpit | <http://moonsols.com/products> | ~ | awesome reverse-engineering |
| 319 | ProcessHacker | <http://processhacker.sourceforge.net> | ~ | awesome reverse-engineering |
| 320 | @SQLMap Devs | <http://sqlmap.sourceforge.net> | ~ | Awesome-WAF |
| 321 | ImpRec | <http://woodmann.com/collaborative/tools/index.php/ImpREC> | ~ | awesome reverse-engineering |
| 322 | The Morning Paper | <https://blog.acolyer.org> | ~ | awesome-web-security |
| 323 | Large-scale analysis of style injection by relative path overwrite | <https://blog.acolyer.org/2018/05/28/large-scale-analysis-of-style-injection-by-relative-path-overwrite> | ~ | awesome-web-security |
| 324 | Andy | <https://blog.zsec.uk> | ~ | awesome-web-security |
| 325 | Timur Daudpota | <https://blurbiz.io> | ~ | awesome-web-security |
| 326 | The most complete guide to finding anyone’s email | <https://blurbiz.io/blog/the-most-complete-guide-to-finding-anyones-email> | ~ | awesome-web-security |
| 327 | Bo0oM | <https://bo0om.ru/author/admin> | ~ | awesome-web-security |
| 328 | Особенности Safari в client-side атаках | <https://bo0om.ru/safari-client-side> | ~ | awesome-web-security |
| 329 | pull_request_template | <https://book.hacktricks.wiki/en/.github/pull_request_template> | ~ | HackTricks-wiki/hacktricks (tree) |
| 330 | macos-auto-start-2026 | <https://book.hacktricks.wiki/en/.github/research/macos-auto-start-2026> | ~ | HackTricks-wiki/hacktricks (tree) |
| 331 | AGENTS | <https://book.hacktricks.wiki/en/AGENTS> | ~ | HackTricks-wiki/hacktricks (tree) |
| 332 | organization-agent | <https://book.hacktricks.wiki/en/organization-agent> | ~ | HackTricks-wiki/hacktricks (tree) |
| 333 | AI-A2A-Protocol | <https://book.hacktricks.wiki/en/src/AI/AI-A2A-Protocol> | ~ | HackTricks-wiki/hacktricks (tree) |
| 334 | AI-Agent-Security-Methodology | <https://book.hacktricks.wiki/en/src/AI/AI-Agent-Security-Methodology> | ~ | HackTricks-wiki/hacktricks (tree) |
| 335 | AI-Assisted-Fuzzing-and-Vulnerability-Discovery | <https://book.hacktricks.wiki/en/src/AI/AI-Assisted-Fuzzing-and-Vulnerability-Discovery> | ~ | HackTricks-wiki/hacktricks (tree) |
| 336 | AI-Assisted-Source-Review-and-Vulnerability-Validation | <https://book.hacktricks.wiki/en/src/AI/AI-Assisted-Source-Review-and-Vulnerability-Validation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 337 | AI-Burp-MCP | <https://book.hacktricks.wiki/en/src/AI/AI-Burp-MCP> | ~ | HackTricks-wiki/hacktricks (tree) |
| 338 | AI-Deep-Learning | <https://book.hacktricks.wiki/en/src/AI/AI-Deep-Learning> | ~ | HackTricks-wiki/hacktricks (tree) |
| 339 | AI-Exposed-Self-Hosted-AI-Services | <https://book.hacktricks.wiki/en/src/AI/AI-Exposed-Self-Hosted-AI-Services> | ~ | HackTricks-wiki/hacktricks (tree) |
| 340 | 0.-basic-llm-concepts | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/0.-basic-llm-concepts> | ~ | HackTricks-wiki/hacktricks (tree) |
| 341 | 1.-tokenizing | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/1.-tokenizing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 342 | 2.-data-sampling | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/2.-data-sampling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 343 | 3.-token-embeddings | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/3.-token-embeddings> | ~ | HackTricks-wiki/hacktricks (tree) |
| 344 | 4.-attention-mechanisms | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/4.-attention-mechanisms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 345 | 5.-llm-architecture | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/5.-llm-architecture> | ~ | HackTricks-wiki/hacktricks (tree) |
| 346 | 6.-pre-training-and-loading-models | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/6.-pre-training-and-loading-models> | ~ | HackTricks-wiki/hacktricks (tree) |
| 347 | 7.0.-lora-improvements-in-fine-tuning | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/7.0.-lora-improvements-in-fine-tuning> | ~ | HackTricks-wiki/hacktricks (tree) |
| 348 | 7.1.-fine-tuning-for-classification | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/7.1.-fine-tuning-for-classification> | ~ | HackTricks-wiki/hacktricks (tree) |
| 349 | 7.2.-fine-tuning-to-follow-instructions | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/7.2.-fine-tuning-to-follow-instructions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 350 | README | <https://book.hacktricks.wiki/en/src/AI/AI-llm-architecture/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 351 | AI-LLM-Gateway-Security | <https://book.hacktricks.wiki/en/src/AI/AI-LLM-Gateway-Security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 352 | AI-MCP-Servers | <https://book.hacktricks.wiki/en/src/AI/AI-MCP-Servers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 353 | AI-Mechanistic-Interpretability-Adversarial-Attacks | <https://book.hacktricks.wiki/en/src/AI/AI-Mechanistic-Interpretability-Adversarial-Attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 354 | AI-Model-Data-Preparation-and-Evaluation | <https://book.hacktricks.wiki/en/src/AI/AI-Model-Data-Preparation-and-Evaluation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 355 | AI-Model-Tools-and-Platforms | <https://book.hacktricks.wiki/en/src/AI/AI-Model-Tools-and-Platforms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 356 | AI-Models-RCE | <https://book.hacktricks.wiki/en/src/AI/AI-Models-RCE> | ~ | HackTricks-wiki/hacktricks (tree) |
| 357 | AI-Prompts | <https://book.hacktricks.wiki/en/src/AI/AI-Prompts> | ~ | HackTricks-wiki/hacktricks (tree) |
| 358 | AI-Reinforcement-Learning-Algorithms | <https://book.hacktricks.wiki/en/src/AI/AI-Reinforcement-Learning-Algorithms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 359 | AI-Risk-Frameworks | <https://book.hacktricks.wiki/en/src/AI/AI-Risk-Frameworks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 360 | AI-Supervised-Learning-Algorithms | <https://book.hacktricks.wiki/en/src/AI/AI-Supervised-Learning-Algorithms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 361 | AI-Unsupervised-Learning-Algorithms | <https://book.hacktricks.wiki/en/src/AI/AI-Unsupervised-Learning-Algorithms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 362 | KYC-Bypass-Using-AI | <https://book.hacktricks.wiki/en/src/AI/KYC-Bypass-Using-AI> | ~ | HackTricks-wiki/hacktricks (tree) |
| 363 | README | <https://book.hacktricks.wiki/en/src/AI/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 364 | Web-Black-Box-AI-Pentester-Bots | <https://book.hacktricks.wiki/en/src/AI/Web-Black-Box-AI-Pentester-Bots> | ~ | HackTricks-wiki/hacktricks (tree) |
| 365 | hacktricks-training | <https://book.hacktricks.wiki/en/src/banners/hacktricks-training> | ~ | HackTricks-wiki/hacktricks (tree) |
| 366 | aw2exec-__malloc_hook | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/aw2exec-__malloc_hook> | ~ | HackTricks-wiki/hacktricks (tree) |
| 367 | aw2exec-__printf_arginfo_table | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/aw2exec-__printf_arginfo_table> | ~ | HackTricks-wiki/hacktricks (tree) |
| 368 | aw2exec-got-plt | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/aw2exec-got-plt> | ~ | HackTricks-wiki/hacktricks (tree) |
| 369 | aw2exec-sips-icc-profile | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/aw2exec-sips-icc-profile> | ~ | HackTricks-wiki/hacktricks (tree) |
| 370 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 371 | www2exec-.dtors-and-.fini_array | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/www2exec-.dtors-and-.fini_array> | ~ | HackTricks-wiki/hacktricks (tree) |
| 372 | www2exec-atexit | <https://book.hacktricks.wiki/en/src/binary-exploitation/arbitrary-write-2-exec/www2exec-atexit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 373 | array-indexing | <https://book.hacktricks.wiki/en/src/binary-exploitation/array-indexing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 374 | elf-tricks | <https://book.hacktricks.wiki/en/src/binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 375 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/basic-stack-binary-exploitation-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 376 | pwntools | <https://book.hacktricks.wiki/en/src/binary-exploitation/basic-stack-binary-exploitation-methodology/tools/pwntools> | ~ | HackTricks-wiki/hacktricks (tree) |
| 377 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/basic-stack-binary-exploitation-methodology/tools/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 378 | chrome-exploiting | <https://book.hacktricks.wiki/en/src/binary-exploitation/chrome-exploiting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 379 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/aslr/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 380 | ret2plt | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/aslr/ret2plt> | ~ | HackTricks-wiki/hacktricks (tree) |
| 381 | ret2ret | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/aslr/ret2ret> | ~ | HackTricks-wiki/hacktricks (tree) |
| 382 | cet-and-shadow-stack | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/cet-and-shadow-stack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 383 | libc-protections | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/libc-protections> | ~ | HackTricks-wiki/hacktricks (tree) |
| 384 | memory-tagging-extension-mte | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/memory-tagging-extension-mte> | ~ | HackTricks-wiki/hacktricks (tree) |
| 385 | no-exec-nx | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/no-exec-nx> | ~ | HackTricks-wiki/hacktricks (tree) |
| 386 | bypassing-canary-and-pie | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/pie/bypassing-canary-and-pie> | ~ | HackTricks-wiki/hacktricks (tree) |
| 387 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/pie/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 388 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 389 | relro | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/relro> | ~ | HackTricks-wiki/hacktricks (tree) |
| 390 | bf-forked-stack-canaries | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries> | ~ | HackTricks-wiki/hacktricks (tree) |
| 391 | print-stack-canary | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/print-stack-canary> | ~ | HackTricks-wiki/hacktricks (tree) |
| 392 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 393 | common-exploiting-problems | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-exploiting-problems> | ~ | HackTricks-wiki/hacktricks (tree) |
| 394 | common-exploiting-problems-unsafe-relocation-fixups | <https://book.hacktricks.wiki/en/src/binary-exploitation/common-exploiting-problems-unsafe-relocation-fixups> | ~ | HackTricks-wiki/hacktricks (tree) |
| 395 | format-strings-arbitrary-read-example | <https://book.hacktricks.wiki/en/src/binary-exploitation/format-strings/format-strings-arbitrary-read-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 396 | format-strings-template | <https://book.hacktricks.wiki/en/src/binary-exploitation/format-strings/format-strings-template> | ~ | HackTricks-wiki/hacktricks (tree) |
| 397 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/format-strings/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 398 | freebsd-kernel-exploitation-vnet-jail-escape | <https://book.hacktricks.wiki/en/src/binary-exploitation/freebsd-kernel-exploitation-vnet-jail-escape> | ~ | HackTricks-wiki/hacktricks (tree) |
| 399 | freebsd-ptrace-rfi-vm_map-prot_exec-bypass-ps5 | <https://book.hacktricks.wiki/en/src/binary-exploitation/freebsd-ptrace-rfi-vm_map-prot_exec-bypass-ps5> | ~ | HackTricks-wiki/hacktricks (tree) |
| 400 | integer-overflow-and-underflow | <https://book.hacktricks.wiki/en/src/binary-exploitation/integer-overflow-and-underflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 401 | coregraphics-pdf-truetype-glyph-rasterizer-oob-write | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/coregraphics-pdf-truetype-glyph-rasterizer-oob-write> | ~ | HackTricks-wiki/hacktricks (tree) |
| 402 | CVE-2020-27950-mach_msg_trailer_t | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/CVE-2020-27950-mach_msg_trailer_t> | ~ | HackTricks-wiki/hacktricks (tree) |
| 403 | CVE-2021-30807-IOMobileFrameBuffer | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/CVE-2021-30807-IOMobileFrameBuffer> | ~ | HackTricks-wiki/hacktricks (tree) |
| 404 | imessage-media-parser-zero-click-coreaudio-pac-bypass | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/imessage-media-parser-zero-click-coreaudio-pac-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 405 | ios-corellium | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/ios-corellium> | ~ | HackTricks-wiki/hacktricks (tree) |
| 406 | ios-driver-embedded-queue-node-uaf | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/ios-driver-embedded-queue-node-uaf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 407 | ios-example-heap-exploit | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/ios-example-heap-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 408 | ios-physical-uaf-iosurface | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/ios-physical-uaf-iosurface> | ~ | HackTricks-wiki/hacktricks (tree) |
| 409 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 410 | webkit-dfg-store-barrier-uaf-angle-oob | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/webkit-dfg-store-barrier-uaf-angle-oob> | ~ | HackTricks-wiki/hacktricks (tree) |
| 411 | webkit-jsc-dfg-slow-path-register-spill | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/webkit-jsc-dfg-slow-path-register-spill> | ~ | HackTricks-wiki/hacktricks (tree) |
| 412 | xnu-vm-map-cow-vnode-toctou | <https://book.hacktricks.wiki/en/src/binary-exploitation/ios-exploiting/xnu-vm-map-cow-vnode-toctou> | ~ | HackTricks-wiki/hacktricks (tree) |
| 413 | bins-and-memory-allocations | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/bins-and-memory-allocations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 414 | double-free | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/double-free> | ~ | HackTricks-wiki/hacktricks (tree) |
| 415 | fast-bin-attack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/fast-bin-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 416 | gnu-obstack-function-pointer-hijack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/gnu-obstack-function-pointer-hijack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 417 | free | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-memory-functions/free> | ~ | HackTricks-wiki/hacktricks (tree) |
| 418 | heap-functions-security-checks | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-memory-functions/heap-functions-security-checks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 419 | malloc-and-sysmalloc | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-memory-functions/malloc-and-sysmalloc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 420 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-memory-functions/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 421 | unlink | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-memory-functions/unlink> | ~ | HackTricks-wiki/hacktricks (tree) |
| 422 | heap-overflow | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/heap-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 423 | house-of-einherjar | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-einherjar> | ~ | HackTricks-wiki/hacktricks (tree) |
| 424 | house-of-force | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-force> | ~ | HackTricks-wiki/hacktricks (tree) |
| 425 | house-of-lore | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-lore> | ~ | HackTricks-wiki/hacktricks (tree) |
| 426 | house-of-orange | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-orange> | ~ | HackTricks-wiki/hacktricks (tree) |
| 427 | house-of-rabbit | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-rabbit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 428 | house-of-roman | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-roman> | ~ | HackTricks-wiki/hacktricks (tree) |
| 429 | house-of-spirit | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/house-of-spirit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 430 | large-bin-attack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/large-bin-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 431 | off-by-one-overflow | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/off-by-one-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 432 | overwriting-a-freed-chunk | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/overwriting-a-freed-chunk> | ~ | HackTricks-wiki/hacktricks (tree) |
| 433 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 434 | tcache-bin-attack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/tcache-bin-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 435 | unlink-attack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/unlink-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 436 | unsorted-bin-attack | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/unsorted-bin-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 437 | first-fit | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/use-after-free/first-fit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 438 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/use-after-free/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 439 | virtualbox-slirp-nat-packet-heap-exploitation | <https://book.hacktricks.wiki/en/src/binary-exploitation/libc-heap/virtualbox-slirp-nat-packet-heap-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 440 | adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw> | ~ | HackTricks-wiki/hacktricks (tree) |
| 441 | af-alg-concurrent-writer-scatterlist-oob | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob> | ~ | HackTricks-wiki/hacktricks (tree) |
| 442 | af-unix-msg-oob-uaf-skb-primitives | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives> | ~ | HackTricks-wiki/hacktricks (tree) |
| 443 | android-binder-ipc-internals-kernel-vulnerability-research | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research> | ~ | HackTricks-wiki/hacktricks (tree) |
| 444 | android-binder-transaction-cleanup-uaf | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/android-binder-transaction-cleanup-uaf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 445 | android-kernel-selinux-bypass | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/android-kernel-selinux-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 446 | arm64-static-linear-map-kaslr-bypass | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 447 | futex-pi-uaf-pipe-buffer-workqueue-usermodehelper | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper> | ~ | HackTricks-wiki/hacktricks (tree) |
| 448 | ksmbd-streams_xattr-oob-write-cve-2025-37947 | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947> | ~ | HackTricks-wiki/hacktricks (tree) |
| 449 | net-sched-action-idr-uaf-cve-2026-53264 | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/net-sched-action-idr-uaf-cve-2026-53264> | ~ | HackTricks-wiki/hacktricks (tree) |
| 450 | nftables-catchall-rollback-uaf | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/nftables-catchall-rollback-uaf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 451 | pixel-bigwave-bigo-job-timeout-uaf-kernel-write | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write> | ~ | HackTricks-wiki/hacktricks (tree) |
| 452 | posix-cpu-timers-toctou-cve-2025-38352 | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352> | ~ | HackTricks-wiki/hacktricks (tree) |
| 453 | qualcomm-kgsl-vbo-bind-race-physical-uaf | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/qualcomm-kgsl-vbo-bind-race-physical-uaf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 454 | usb-audio-descriptor-oob-kaslr-leak | <https://book.hacktricks.wiki/en/src/binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak> | ~ | HackTricks-wiki/hacktricks (tree) |
| 455 | qemu-kvm-vm-escape-chains | <https://book.hacktricks.wiki/en/src/binary-exploitation/qemu-kvm-vm-escape-chains> | ~ | HackTricks-wiki/hacktricks (tree) |
| 456 | brop-blind-return-oriented-programming | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/brop-blind-return-oriented-programming> | ~ | HackTricks-wiki/hacktricks (tree) |
| 457 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 458 | ret2csu | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2csu> | ~ | HackTricks-wiki/hacktricks (tree) |
| 459 | ret2dlresolve | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2dlresolve> | ~ | HackTricks-wiki/hacktricks (tree) |
| 460 | ret2esp-ret2reg | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2esp-ret2reg> | ~ | HackTricks-wiki/hacktricks (tree) |
| 461 | one-gadget | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2lib/one-gadget> | ~ | HackTricks-wiki/hacktricks (tree) |
| 462 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2lib/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 463 | ret2lib-printf-leak-arm64 | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2lib/ret2lib-printf-leak-arm64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 464 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 465 | rop-leaking-libc-template | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address/rop-leaking-libc-template> | ~ | HackTricks-wiki/hacktricks (tree) |
| 466 | ret2vdso | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/ret2vdso> | ~ | HackTricks-wiki/hacktricks (tree) |
| 467 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 468 | ret2syscall-arm64 | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/ret2syscall-arm64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 469 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 470 | srop-arm64 | <https://book.hacktricks.wiki/en/src/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/srop-arm64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 471 | pointer-redirecting | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/pointer-redirecting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 472 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 473 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/ret2win/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 474 | ret2win-arm64 | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/ret2win/ret2win-arm64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 475 | stack-pivoting | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/stack-pivoting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 476 | README | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/stack-shellcode/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 477 | stack-shellcode-arm64 | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/stack-shellcode/stack-shellcode-arm64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 478 | uninitialized-variables | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/uninitialized-variables> | ~ | HackTricks-wiki/hacktricks (tree) |
| 479 | windows-seh-overflow | <https://book.hacktricks.wiki/en/src/binary-exploitation/stack-overflow/windows-seh-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 480 | virtualbox-vmsvga-cotable-uaf-escape | <https://book.hacktricks.wiki/en/src/binary-exploitation/virtualbox-vmsvga-cotable-uaf-escape> | ~ | HackTricks-wiki/hacktricks (tree) |
| 481 | vm-escape-and-hypervisor-exploitation | <https://book.hacktricks.wiki/en/src/binary-exploitation/vm-escape-and-hypervisor-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 482 | vmware-hgfs-oob-read-aslr-bypass | <https://book.hacktricks.wiki/en/src/binary-exploitation/vmware-hgfs-oob-read-aslr-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 483 | vmware-workstation-pvscsi-lfh-escape | <https://book.hacktricks.wiki/en/src/binary-exploitation/vmware-workstation-pvscsi-lfh-escape> | ~ | HackTricks-wiki/hacktricks (tree) |
| 484 | windows-exploiting-basic-guide-oscp-lvl | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-exploiting-basic-guide-oscp-lvl> | ~ | HackTricks-wiki/hacktricks (tree) |
| 485 | afd-rio-buffer-uaf | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 486 | uasp-report-luns-cache-size-oob-write | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write> | ~ | HackTricks-wiki/hacktricks (tree) |
| 487 | usb-midi-packet-size-pool-overflow | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 488 | windows-kernel-type-confusion-to-npfs-arbitrary-rw | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw> | ~ | HackTricks-wiki/hacktricks (tree) |
| 489 | windows-userland-heap-grooming | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-userland-heap-grooming> | ~ | HackTricks-wiki/hacktricks (tree) |
| 490 | windows-vectored-overloading | <https://book.hacktricks.wiki/en/src/binary-exploitation/windows-vectored-overloading> | ~ | HackTricks-wiki/hacktricks (tree) |
| 491 | defi-amm-hook-precision | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/defi-amm-hook-precision> | ~ | HackTricks-wiki/hacktricks (tree) |
| 492 | defi-amm-virtual-balance-cache-exploitation | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/defi-amm-virtual-balance-cache-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 493 | erc-4337-smart-account-security-pitfalls | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/erc-4337-smart-account-security-pitfalls> | ~ | HackTricks-wiki/hacktricks (tree) |
| 494 | investment-terms | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/investment-terms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 495 | README | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 496 | state-divergence-default-value-authorization-bypasses | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/state-divergence-default-value-authorization-bypasses> | ~ | HackTricks-wiki/hacktricks (tree) |
| 497 | value-centric-web3-red-teaming | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/value-centric-web3-red-teaming> | ~ | HackTricks-wiki/hacktricks (tree) |
| 498 | web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover | <https://book.hacktricks.wiki/en/src/blockchain/blockchain-and-crypto-currencies/web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover> | ~ | HackTricks-wiki/hacktricks (tree) |
| 499 | mutation-testing-with-slither | <https://book.hacktricks.wiki/en/src/blockchain/smart-contract-security/mutation-testing-with-slither> | ~ | HackTricks-wiki/hacktricks (tree) |
| 500 | README | <https://book.hacktricks.wiki/en/src/crypto/crypto-in-malware/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 501 | README | <https://book.hacktricks.wiki/en/src/crypto/hashes/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 502 | README | <https://book.hacktricks.wiki/en/src/crypto/public-key/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 503 | README | <https://book.hacktricks.wiki/en/src/crypto/public-key/rsa/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 504 | README | <https://book.hacktricks.wiki/en/src/crypto/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 505 | README | <https://book.hacktricks.wiki/en/src/crypto/symmetric/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 506 | README | <https://book.hacktricks.wiki/en/src/crypto/tls-and-certificates/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 507 | archive-extraction-path-traversal | <https://book.hacktricks.wiki/en/src/generic-hacking/archive-extraction-path-traversal> | ~ | HackTricks-wiki/hacktricks (tree) |
| 508 | brute-force | <https://book.hacktricks.wiki/en/src/generic-hacking/brute-force> | ~ | HackTricks-wiki/hacktricks (tree) |
| 509 | exfiltration | <https://book.hacktricks.wiki/en/src/generic-hacking/exfiltration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 510 | expose-local-to-the-internet | <https://book.hacktricks.wiki/en/src/generic-hacking/expose-local-to-the-internet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 511 | full-ttys | <https://book.hacktricks.wiki/en/src/generic-hacking/reverse-shells/full-ttys> | ~ | HackTricks-wiki/hacktricks (tree) |
| 512 | linux | <https://book.hacktricks.wiki/en/src/generic-hacking/reverse-shells/linux> | ~ | HackTricks-wiki/hacktricks (tree) |
| 513 | msfvenom | <https://book.hacktricks.wiki/en/src/generic-hacking/reverse-shells/msfvenom> | ~ | HackTricks-wiki/hacktricks (tree) |
| 514 | README | <https://book.hacktricks.wiki/en/src/generic-hacking/reverse-shells/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 515 | windows | <https://book.hacktricks.wiki/en/src/generic-hacking/reverse-shells/windows> | ~ | HackTricks-wiki/hacktricks (tree) |
| 516 | search-exploits | <https://book.hacktricks.wiki/en/src/generic-hacking/search-exploits> | ~ | HackTricks-wiki/hacktricks (tree) |
| 517 | tunneling-and-port-forwarding | <https://book.hacktricks.wiki/en/src/generic-hacking/tunneling-and-port-forwarding> | ~ | HackTricks-wiki/hacktricks (tree) |
| 518 | adaptixc2-config-extraction-and-ttps | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/adaptixc2-config-extraction-and-ttps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 519 | android-forensics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 520 | android-malware-post-exploitation | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/android-malware-post-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 521 | anti-forensic-techniques | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/anti-forensic-techniques> | ~ | HackTricks-wiki/hacktricks (tree) |
| 522 | docker-forensics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/docker-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 523 | file-integrity-monitoring | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/file-integrity-monitoring> | ~ | HackTricks-wiki/hacktricks (tree) |
| 524 | image-acquisition-and-mount | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount> | ~ | HackTricks-wiki/hacktricks (tree) |
| 525 | ios-backup-forensics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/ios-backup-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 526 | linux-forensics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/linux-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 527 | malware-analysis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 528 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 529 | volatility-cheatsheet | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 530 | file-data-carving-recovery-tools | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools> | ~ | HackTricks-wiki/hacktricks (tree) |
| 531 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 532 | dnscat-exfiltration | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/dnscat-exfiltration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 533 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 534 | suricata-and-iptables-cheatsheet | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/suricata-and-iptables-cheatsheet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 535 | usb-keystrokes | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/usb-keystrokes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 536 | wifi-pcap-analysis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/wifi-pcap-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 537 | wireshark-tricks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/wireshark-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 538 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 539 | .pyc | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 540 | browser-artifacts | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts> | ~ | HackTricks-wiki/hacktricks (tree) |
| 541 | desofuscation-vbs-cscript.exe | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/desofuscation-vbs-cscript.exe> | ~ | HackTricks-wiki/hacktricks (tree) |
| 542 | discord-cache-forensics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/discord-cache-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 543 | local-cloud-storage | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 544 | mach-o-entitlements-and-ipsw-indexing | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 545 | office-file-analysis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 546 | pdf-file-analysis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/pdf-file-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 547 | png-tricks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 548 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 549 | structural-file-format-exploit-detection | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/structural-file-format-exploit-detection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 550 | svg-font-glyph-analysis-and-web-drm-deobfuscation | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/svg-font-glyph-analysis-and-web-drm-deobfuscation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 551 | video-and-audio-file-analysis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/video-and-audio-file-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 552 | zips-tricks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 553 | interesting-windows-registry-keys | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics/interesting-windows-registry-keys> | ~ | HackTricks-wiki/hacktricks (tree) |
| 554 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 555 | database-leaks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/external-recon-methodology/database-leaks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 556 | github-leaked-secrets | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 557 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/external-recon-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 558 | reconnaissance-and-threat-intelligence-apis | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/external-recon-methodology/reconnaissance-and-threat-intelligence-apis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 559 | wide-source-code-search | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/external-recon-methodology/wide-source-code-search> | ~ | HackTricks-wiki/hacktricks (tree) |
| 560 | fuzzing | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/fuzzing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 561 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/lua/bypass-lua-sandboxes/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 562 | pentesting-methodology | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-methodology> | ~ | HackTricks-wiki/hacktricks (tree) |
| 563 | dds-rtps-security | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/dds-rtps-security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 564 | dhcpv6 | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/dhcpv6> | ~ | HackTricks-wiki/hacktricks (tree) |
| 565 | eigrp-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/eigrp-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 566 | glbp-and-hsrp-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/glbp-and-hsrp-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 567 | ids-evasion | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/ids-evasion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 568 | lateral-vlan-segmentation-bypass | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/lateral-vlan-segmentation-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 569 | network-protocols-explained-esp | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/network-protocols-explained-esp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 570 | nmap-summary-esp | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/nmap-summary-esp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 571 | pentesting-ipv6 | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/pentesting-ipv6> | ~ | HackTricks-wiki/hacktricks (tree) |
| 572 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 573 | spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 574 | spoofing-ssdp-and-upnp-devices | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices> | ~ | HackTricks-wiki/hacktricks (tree) |
| 575 | telecom-network-exploitation | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/telecom-network-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 576 | webrtc-dos | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-network/webrtc-dos> | ~ | HackTricks-wiki/hacktricks (tree) |
| 577 | captive-portals | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/captive-portals> | ~ | HackTricks-wiki/hacktricks (tree) |
| 578 | eap-methods | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/eap-methods> | ~ | HackTricks-wiki/hacktricks (tree) |
| 579 | enable-nexmon-monitor-and-injection-on-android | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/enable-nexmon-monitor-and-injection-on-android> | ~ | HackTricks-wiki/hacktricks (tree) |
| 580 | evil-twin-eap-tls | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/evil-twin-eap-tls> | ~ | HackTricks-wiki/hacktricks (tree) |
| 581 | evil-twin-rogue-ap-and-client-association-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/evil-twin-rogue-ap-and-client-association-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 582 | fragattacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/fragattacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 583 | modern-wifi-roaming-6ghz-and-mlo | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/modern-wifi-roaming-6ghz-and-mlo> | ~ | HackTricks-wiki/hacktricks (tree) |
| 584 | open-wifi-opn | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/open-wifi-opn> | ~ | HackTricks-wiki/hacktricks (tree) |
| 585 | owe | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/owe> | ~ | HackTricks-wiki/hacktricks (tree) |
| 586 | passpoint-hotspot-2.0-and-openroaming | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/passpoint-hotspot-2.0-and-openroaming> | ~ | HackTricks-wiki/hacktricks (tree) |
| 587 | protected-management-frames-pmf | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/protected-management-frames-pmf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 588 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 589 | wep | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wep> | ~ | HackTricks-wiki/hacktricks (tree) |
| 590 | wifi-client-and-supplicant-assessment | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment> | ~ | HackTricks-wiki/hacktricks (tree) |
| 591 | wifi-defense-monitoring-and-wids | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-defense-monitoring-and-wids> | ~ | HackTricks-wiki/hacktricks (tree) |
| 592 | wifi-direct-and-iot-provisioning | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-direct-and-iot-provisioning> | ~ | HackTricks-wiki/hacktricks (tree) |
| 593 | wifi-dos-and-management-frame-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-dos-and-management-frame-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 594 | wifi-easy-connect-dpp | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-easy-connect-dpp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 595 | wifi-fundamentals | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-fundamentals> | ~ | HackTricks-wiki/hacktricks (tree) |
| 596 | wifi-hardware-drivers-and-linux | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-hardware-drivers-and-linux> | ~ | HackTricks-wiki/hacktricks (tree) |
| 597 | wifi-mesh-and-easymesh | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-mesh-and-easymesh> | ~ | HackTricks-wiki/hacktricks (tree) |
| 598 | wifi-post-association-and-client-isolation-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 599 | wifi-privacy-tracking-and-side-channels | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-privacy-tracking-and-side-channels> | ~ | HackTricks-wiki/hacktricks (tree) |
| 600 | wifi-reconnaissance-and-wardriving | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-reconnaissance-and-wardriving> | ~ | HackTricks-wiki/hacktricks (tree) |
| 601 | wifi-reconnaissance-setups | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-reconnaissance-setups> | ~ | HackTricks-wiki/hacktricks (tree) |
| 602 | wifi-tools-reference | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wifi-tools-reference> | ~ | HackTricks-wiki/hacktricks (tree) |
| 603 | wpa-enterprise-8021x | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wpa-enterprise-8021x> | ~ | HackTricks-wiki/hacktricks (tree) |
| 604 | wpa-tkip | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wpa-tkip> | ~ | HackTricks-wiki/hacktricks (tree) |
| 605 | wpa2-personal-psk | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wpa2-personal-psk> | ~ | HackTricks-wiki/hacktricks (tree) |
| 606 | wpa3-personal-sae | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wpa3-personal-sae> | ~ | HackTricks-wiki/hacktricks (tree) |
| 607 | wps | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/pentesting-wifi/wps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 608 | ai-agent-abuse-local-ai-cli-tools-and-mcp | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 609 | ai-agent-mode-phishing-abusing-hosted-agent-browsers | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 610 | clipboard-hijacking | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 611 | clone-a-website | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/clone-a-website> | ~ | HackTricks-wiki/hacktricks (tree) |
| 612 | detecting-phising | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/detecting-phising> | ~ | HackTricks-wiki/hacktricks (tree) |
| 613 | discord-invite-hijacking | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/discord-invite-hijacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 614 | homograph-attacks | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/homograph-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 615 | mobile-phishing-malicious-apps | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 616 | phishing-documents | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/phishing-documents> | ~ | HackTricks-wiki/hacktricks (tree) |
| 617 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/phishing-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 618 | post-exploitation-collection-tools | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/post-exploitation-collection-tools> | ~ | HackTricks-wiki/hacktricks (tree) |
| 619 | proof-assistant-formal-verification-security | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/proof-assistant-formal-verification-security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 620 | basic-python | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/basic-python> | ~ | HackTricks-wiki/hacktricks (tree) |
| 621 | js2py-sandbox-escape-cve-2024-28397 | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/bypass-python-sandboxes/js2py-sandbox-escape-cve-2024-28397> | ~ | HackTricks-wiki/hacktricks (tree) |
| 622 | load_name-load_const-opcode-oob-read | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/bypass-python-sandboxes/load_name-load_const-opcode-oob-read> | ~ | HackTricks-wiki/hacktricks (tree) |
| 623 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/bypass-python-sandboxes/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 624 | reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733 | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/bypass-python-sandboxes/reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733> | ~ | HackTricks-wiki/hacktricks (tree) |
| 625 | class-pollution-pythons-prototype-pollution | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 626 | keras-model-deserialization-rce-and-gadget-hunting | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 627 | pyscript | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/pyscript> | ~ | HackTricks-wiki/hacktricks (tree) |
| 628 | python-internal-read-gadgets | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/python-internal-read-gadgets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 629 | README | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 630 | web-requests | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/python/web-requests> | ~ | HackTricks-wiki/hacktricks (tree) |
| 631 | rust-basics | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/rust-basics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 632 | side-channel-attacks-on-messaging-protocols | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/side-channel-attacks-on-messaging-protocols> | ~ | HackTricks-wiki/hacktricks (tree) |
| 633 | threat-modeling | <https://book.hacktricks.wiki/en/src/generic-methodologies-and-resources/threat-modeling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 634 | escaping-from-gui-applications | <https://book.hacktricks.wiki/en/src/hardware-physical-access/escaping-from-gui-applications> | ~ | HackTricks-wiki/hacktricks (tree) |
| 635 | android-mediatek-secure-boot-bl2_ext-bypass-el3 | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/android-mediatek-secure-boot-bl2_ext-bypass-el3> | ~ | HackTricks-wiki/hacktricks (tree) |
| 636 | bootloader-testing | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/bootloader-testing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 637 | firmware-integrity | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/firmware-integrity> | ~ | HackTricks-wiki/hacktricks (tree) |
| 638 | mediatek-xflash-carbonara-da2-hash-bypass | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/mediatek-xflash-carbonara-da2-hash-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 639 | README | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 640 | synology-encrypted-archive-decryption | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/synology-encrypted-archive-decryption> | ~ | HackTricks-wiki/hacktricks (tree) |
| 641 | uefi-ifr-nvram-security-setting-patching | <https://book.hacktricks.wiki/en/src/hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching> | ~ | HackTricks-wiki/hacktricks (tree) |
| 642 | arm-coresight-instruction-tracing | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/arm-coresight-instruction-tracing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 643 | fault_injection_attacks | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/fault_injection_attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 644 | i2c | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/i2c> | ~ | HackTricks-wiki/hacktricks (tree) |
| 645 | jtag | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/jtag> | ~ | HackTricks-wiki/hacktricks (tree) |
| 646 | radio | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/radio> | ~ | HackTricks-wiki/hacktricks (tree) |
| 647 | README | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 648 | side_channel_analysis | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/side_channel_analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 649 | spi | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/spi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 650 | uart | <https://book.hacktricks.wiki/en/src/hardware-physical-access/hardware-hacking/uart> | ~ | HackTricks-wiki/hacktricks (tree) |
| 651 | physical-attacks | <https://book.hacktricks.wiki/en/src/hardware-physical-access/physical-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 652 | fissure-the-rf-framework | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/fissure-the-rf-framework> | ~ | HackTricks-wiki/hacktricks (tree) |
| 653 | fz-125khz-rfid | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/fz-125khz-rfid> | ~ | HackTricks-wiki/hacktricks (tree) |
| 654 | fz-ibutton | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/fz-ibutton> | ~ | HackTricks-wiki/hacktricks (tree) |
| 655 | fz-infrared | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/fz-infrared> | ~ | HackTricks-wiki/hacktricks (tree) |
| 656 | fz-nfc | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/fz-nfc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 657 | fz-sub-ghz | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/fz-sub-ghz> | ~ | HackTricks-wiki/hacktricks (tree) |
| 658 | README | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/flipper-zero/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 659 | ibutton | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/ibutton> | ~ | HackTricks-wiki/hacktricks (tree) |
| 660 | infrared | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/infrared> | ~ | HackTricks-wiki/hacktricks (tree) |
| 661 | low-power-wide-area-network | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/low-power-wide-area-network> | ~ | HackTricks-wiki/hacktricks (tree) |
| 662 | maxiprox-mobile-cloner | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/maxiprox-mobile-cloner> | ~ | HackTricks-wiki/hacktricks (tree) |
| 663 | pentesting-ble-bluetooth-low-energy | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/pentesting-ble-bluetooth-low-energy> | ~ | HackTricks-wiki/hacktricks (tree) |
| 664 | pentesting-rfid | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/pentesting-rfid> | ~ | HackTricks-wiki/hacktricks (tree) |
| 665 | proxmark-3 | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/proxmark-3> | ~ | HackTricks-wiki/hacktricks (tree) |
| 666 | README | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 667 | sub-ghz-rf | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/sub-ghz-rf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 668 | vsat-forward-link-injection | <https://book.hacktricks.wiki/en/src/hardware-physical-access/radio-hacking/vsat-forward-link-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 669 | README | <https://book.hacktricks.wiki/en/src/industrial-control-systems/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 670 | assessment-and-hardening | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/assessment-and-hardening> | ~ | HackTricks-wiki/hacktricks (tree) |
| 671 | authorization-plugins | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/authorization-plugins> | ~ | HackTricks-wiki/hacktricks (tree) |
| 672 | distroless | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/distroless> | ~ | HackTricks-wiki/hacktricks (tree) |
| 673 | image-security-and-secrets | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/image-security-and-secrets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 674 | privileged-containers | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/privileged-containers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 675 | apparmor | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/apparmor> | ~ | HackTricks-wiki/hacktricks (tree) |
| 676 | capabilities | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/capabilities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 677 | cgroups | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/cgroups> | ~ | HackTricks-wiki/hacktricks (tree) |
| 678 | masked-paths | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/masked-paths> | ~ | HackTricks-wiki/hacktricks (tree) |
| 679 | cgroup-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/cgroup-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 680 | ipc-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/ipc-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 681 | mount-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/mount-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 682 | network-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/network-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 683 | pid-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/pid-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 684 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 685 | time-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/time-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 686 | user-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/user-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 687 | uts-namespace | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/namespaces/uts-namespace> | ~ | HackTricks-wiki/hacktricks (tree) |
| 688 | no-new-privileges | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/no-new-privileges> | ~ | HackTricks-wiki/hacktricks (tree) |
| 689 | read-only-paths | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/read-only-paths> | ~ | HackTricks-wiki/hacktricks (tree) |
| 690 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 691 | seccomp | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/seccomp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 692 | selinux | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/protections/selinux> | ~ | HackTricks-wiki/hacktricks (tree) |
| 693 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 694 | runtime-api-and-daemon-exposure | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/runtime-api-and-daemon-exposure> | ~ | HackTricks-wiki/hacktricks (tree) |
| 695 | runtimes-and-engines | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/runtimes-and-engines> | ~ | HackTricks-wiki/hacktricks (tree) |
| 696 | sensitive-host-mounts | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/container-security/sensitive-host-mounts> | ~ | HackTricks-wiki/hacktricks (tree) |
| 697 | containerd-ctr-privilege-escalation | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/containerd-ctr-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 698 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 699 | runc-privilege-escalation | <https://book.hacktricks.wiki/en/src/linux-hardening/containers-namespaces/runc-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 700 | ld.so.conf-example | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/ld.so.conf-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 701 | linux-capabilities | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/linux-capabilities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 702 | nfs-no_root_squash-misconfiguration-pe | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe> | ~ | HackTricks-wiki/hacktricks (tree) |
| 703 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 704 | selinux | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/selinux> | ~ | HackTricks-wiki/hacktricks (tree) |
| 705 | suid-sgid-and-acl-triage | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/suid-sgid-and-acl-triage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 706 | suid-shared-library-and-linker-abuse | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/suid-shared-library-and-linker-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 707 | wildcards-spare-tricks | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/wildcards-spare-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 708 | write-to-root | <https://book.hacktricks.wiki/en/src/linux-hardening/interesting-files-permissions/write-to-root> | ~ | HackTricks-wiki/hacktricks (tree) |
| 709 | ddexec | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/ddexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 710 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 711 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/bypass-linux-restrictions/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 712 | linux-environment-variables | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/linux-environment-variables> | ~ | HackTricks-wiki/hacktricks (tree) |
| 713 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/linux-privilege-escalation/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 714 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 715 | shell-startup-aliases-and-history | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/shell-startup-aliases-and-history> | ~ | HackTricks-wiki/hacktricks (tree) |
| 716 | useful-linux-commands | <https://book.hacktricks.wiki/en/src/linux-hardening/linux-basics/useful-linux-commands> | ~ | HackTricks-wiki/hacktricks (tree) |
| 717 | escaping-from-limited-bash | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/escaping-from-limited-bash> | ~ | HackTricks-wiki/hacktricks (tree) |
| 718 | filesystem-inodes-and-recovery | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/filesystem-inodes-and-recovery> | ~ | HackTricks-wiki/hacktricks (tree) |
| 719 | filesystem-links-and-file-descriptors | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/filesystem-links-and-file-descriptors> | ~ | HackTricks-wiki/hacktricks (tree) |
| 720 | copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431 | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-lpe-cves/copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431> | ~ | HackTricks-wiki/hacktricks (tree) |
| 721 | linux-ptrace-exit-race-pidfd_getfd-fd-theft | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft> | ~ | HackTricks-wiki/hacktricks (tree) |
| 722 | open-vswitch-forwarded-skb-marker-stripping-esp-page-cache-write | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-lpe-cves/open-vswitch-forwarded-skb-marker-stripping-esp-page-cache-write> | ~ | HackTricks-wiki/hacktricks (tree) |
| 723 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-lpe-cves/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 724 | vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244 | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244> | ~ | HackTricks-wiki/hacktricks (tree) |
| 725 | kernel-modules-and-modprobe | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-modules-and-modprobe> | ~ | HackTricks-wiki/hacktricks (tree) |
| 726 | kernel-vulnerability-assessment | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/kernel-vulnerability-assessment> | ~ | HackTricks-wiki/hacktricks (tree) |
| 727 | linux-privilege-escalation-checklist | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/linux-privilege-escalation-checklist> | ~ | HackTricks-wiki/hacktricks (tree) |
| 728 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 729 | sudo-command-abuse | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/sudo-command-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 730 | suse-session-and-disk-service-escalation | <https://book.hacktricks.wiki/en/src/linux-hardening/main-system-information/suse-session-and-disk-service-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 731 | cisco-vmanage | <https://book.hacktricks.wiki/en/src/linux-hardening/network-information/cisco-vmanage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 732 | local-network-and-socket-triage | <https://book.hacktricks.wiki/en/src/linux-hardening/network-information/local-network-and-socket-triage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 733 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/network-information/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 734 | socket-command-injection | <https://book.hacktricks.wiki/en/src/linux-hardening/network-information/socket-command-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 735 | traffic-capture-and-firewall-egress | <https://book.hacktricks.wiki/en/src/linux-hardening/network-information/traffic-capture-and-firewall-egress> | ~ | HackTricks-wiki/hacktricks (tree) |
| 736 | cloud-instance-metadata | <https://book.hacktricks.wiki/en/src/linux-hardening/post-exploitation/cloud-instance-metadata> | ~ | HackTricks-wiki/hacktricks (tree) |
| 737 | linux-fileless-execution | <https://book.hacktricks.wiki/en/src/linux-hardening/post-exploitation/linux-fileless-execution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 738 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/post-exploitation/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 739 | trojanized-system-daemons-and-reverse-proxies | <https://book.hacktricks.wiki/en/src/linux-hardening/post-exploitation/trojanized-system-daemons-and-reverse-proxies> | ~ | HackTricks-wiki/hacktricks (tree) |
| 740 | cron-and-systemd-timers | <https://book.hacktricks.wiki/en/src/linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 741 | d-bus-enumeration-and-command-injection-privilege-escalation | <https://book.hacktricks.wiki/en/src/linux-hardening/processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 742 | payloads-to-execute | <https://book.hacktricks.wiki/en/src/linux-hardening/processes-crontab-systemd-dbus/payloads-to-execute> | ~ | HackTricks-wiki/hacktricks (tree) |
| 743 | process-enumeration-and-service-paths | <https://book.hacktricks.wiki/en/src/linux-hardening/processes-crontab-systemd-dbus/process-enumeration-and-service-paths> | ~ | HackTricks-wiki/hacktricks (tree) |
| 744 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/processes-crontab-systemd-dbus/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 745 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 746 | android-rooting-frameworks-manager-auth-bypass-syscall-hook | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook> | ~ | HackTricks-wiki/hacktricks (tree) |
| 747 | databases-and-secret-material | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/databases-and-secret-material> | ~ | HackTricks-wiki/hacktricks (tree) |
| 748 | electron-cef-chromium-debugger-abuse | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/electron-cef-chromium-debugger-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 749 | freeipa-pentesting | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/freeipa-pentesting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 750 | local-web-and-auth-services | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/local-web-and-auth-services> | ~ | HackTricks-wiki/hacktricks (tree) |
| 751 | logstash | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/logstash> | ~ | HackTricks-wiki/hacktricks (tree) |
| 752 | pam-pluggable-authentication-modules | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/pam-pluggable-authentication-modules> | ~ | HackTricks-wiki/hacktricks (tree) |
| 753 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 754 | splunk-lpe-and-persistence | <https://book.hacktricks.wiki/en/src/linux-hardening/software-information/splunk-lpe-and-persistence> | ~ | HackTricks-wiki/hacktricks (tree) |
| 755 | euid-ruid-suid | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/euid-ruid-suid> | ~ | HackTricks-wiki/hacktricks (tree) |
| 756 | lxd-privilege-escalation | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/interesting-groups-linux-pe/lxd-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 757 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/interesting-groups-linux-pe/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 758 | linux-active-directory | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/linux-active-directory> | ~ | HackTricks-wiki/hacktricks (tree) |
| 759 | README | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 760 | ssh-forward-agent-exploitation | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/ssh-forward-agent-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 761 | user-and-session-triage | <https://book.hacktricks.wiki/en/src/linux-hardening/user-information/user-and-session-triage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 762 | macos-auto-start-locations | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-auto-start-locations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 763 | macos-keychain | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-red-teaming/macos-keychain> | ~ | HackTricks-wiki/hacktricks (tree) |
| 764 | enrolling-devices-in-other-organisations | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-red-teaming/macos-mdm/enrolling-devices-in-other-organisations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 765 | macos-serial-number | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-red-teaming/macos-mdm/macos-serial-number> | ~ | HackTricks-wiki/hacktricks (tree) |
| 766 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-red-teaming/macos-mdm/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 767 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-red-teaming/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 768 | macos-iokit | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/macos-iokit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 769 | macos-kernel-extensions | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/macos-kernel-extensions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 770 | macos-kernel-vulnerabilities | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/macos-kernel-vulnerabilities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 771 | macos-nvram | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/macos-nvram> | ~ | HackTricks-wiki/hacktricks (tree) |
| 772 | macos-system-extensions | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/macos-system-extensions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 773 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/mac-os-architecture/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 774 | macos-applefs | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-applefs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 775 | arm64-basic-assembly | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly> | ~ | HackTricks-wiki/hacktricks (tree) |
| 776 | introduction-to-x64 | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/introduction-to-x64> | ~ | HackTricks-wiki/hacktricks (tree) |
| 777 | objects-in-memory | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory> | ~ | HackTricks-wiki/hacktricks (tree) |
| 778 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 779 | macos-basic-objective-c | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-basic-objective-c> | ~ | HackTricks-wiki/hacktricks (tree) |
| 780 | macos-bypassing-firewalls | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-bypassing-firewalls> | ~ | HackTricks-wiki/hacktricks (tree) |
| 781 | macos-defensive-apps | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-defensive-apps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 782 | macos-file-extension-apps | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-file-extension-apps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 783 | macos-bundles | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-bundles> | ~ | HackTricks-wiki/hacktricks (tree) |
| 784 | macos-installers-abuse | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 785 | macos-memory-dumping | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-memory-dumping> | ~ | HackTricks-wiki/hacktricks (tree) |
| 786 | macos-sensitive-locations | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-sensitive-locations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 787 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 788 | universal-binaries-and-mach-o-format | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format> | ~ | HackTricks-wiki/hacktricks (tree) |
| 789 | macos-gcd-grand-central-dispatch | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-gcd-grand-central-dispatch> | ~ | HackTricks-wiki/hacktricks (tree) |
| 790 | macos-privilege-escalation | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 791 | arm64-arm64e-call-stack-spoofing | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/arm64-arm64e-call-stack-spoofing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 792 | macos-.net-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-.net-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 793 | macos-automator-preference-panes-nsservices | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-automator-preference-panes-nsservices> | ~ | HackTricks-wiki/hacktricks (tree) |
| 794 | macos-bash-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 795 | macos-chromium-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 796 | macos-dirty-nib | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-dirty-nib> | ~ | HackTricks-wiki/hacktricks (tree) |
| 797 | macos-electron-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 798 | macos-erlang-elixir-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-erlang-elixir-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 799 | macos-function-hooking | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-function-hooking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 800 | macos-mig-mach-interface-generator | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator> | ~ | HackTricks-wiki/hacktricks (tree) |
| 801 | macos-thread-injection-via-task-port | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port> | ~ | HackTricks-wiki/hacktricks (tree) |
| 802 | macos-xpc-authorization | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 803 | macos-pid-reuse | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-connecting-process-check/macos-pid-reuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 804 | macos-xpc_connection_get_audit_token-attack | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-connecting-process-check/macos-xpc_connection_get_audit_token-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 805 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-connecting-process-check/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 806 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 807 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 808 | macos-java-apps-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-java-apps-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 809 | macos-julia-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-julia-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 810 | macos-dyld-hijacking-and-dyld_insert_libraries | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries> | ~ | HackTricks-wiki/hacktricks (tree) |
| 811 | macos-dyld-process | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-process> | ~ | HackTricks-wiki/hacktricks (tree) |
| 812 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 813 | macos-lua-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-lua-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 814 | macos-nodejs-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-nodejs-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 815 | macos-octave-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-octave-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 816 | macos-perl-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-perl-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 817 | macos-php-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-php-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 818 | macos-powershell-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 819 | macos-python-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-python-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 820 | macos-quicklook-generators | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-quicklook-generators> | ~ | HackTricks-wiki/hacktricks (tree) |
| 821 | macos-r-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-r-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 822 | macos-ruby-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ruby-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 823 | macos-vim-applications-injection | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-vim-applications-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 824 | macos-xpc-mach-services-abuse | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-xpc-mach-services-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 825 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 826 | reflective-mach-o-loading | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/reflective-mach-o-loading> | ~ | HackTricks-wiki/hacktricks (tree) |
| 827 | macos-protocols | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-protocols> | ~ | HackTricks-wiki/hacktricks (tree) |
| 828 | macos-amfi-applemobilefileintegrity | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-amfi-applemobilefileintegrity> | ~ | HackTricks-wiki/hacktricks (tree) |
| 829 | macos-authorizations-db-and-authd | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-authorizations-db-and-authd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 830 | macos-code-signing | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 831 | macos-code-signing-weaknesses-and-sandbox-escapes | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 832 | macos-dangerous-entitlements | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements> | ~ | HackTricks-wiki/hacktricks (tree) |
| 833 | macos-xattr-acls-extra-stuff | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-fs-tricks/macos-xattr-acls-extra-stuff> | ~ | HackTricks-wiki/hacktricks (tree) |
| 834 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-fs-tricks/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 835 | macos-gatekeeper | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-gatekeeper> | ~ | HackTricks-wiki/hacktricks (tree) |
| 836 | macos-input-monitoring-screen-capture-accessibility | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility> | ~ | HackTricks-wiki/hacktricks (tree) |
| 837 | macos-launch-environment-constraints | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-launch-environment-constraints> | ~ | HackTricks-wiki/hacktricks (tree) |
| 838 | macos-macf-mandatory-access-control-framework | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-macf-mandatory-access-control-framework> | ~ | HackTricks-wiki/hacktricks (tree) |
| 839 | macos-default-sandbox-debug | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/macos-default-sandbox-debug> | ~ | HackTricks-wiki/hacktricks (tree) |
| 840 | macos-office-sandbox-bypasses | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/macos-sandbox-debug-and-bypass/macos-office-sandbox-bypasses> | ~ | HackTricks-wiki/hacktricks (tree) |
| 841 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/macos-sandbox-debug-and-bypass/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 842 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 843 | macos-sealed-system-volume-and-datavault | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sealed-system-volume-and-datavault> | ~ | HackTricks-wiki/hacktricks (tree) |
| 844 | macos-sip | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sip> | ~ | HackTricks-wiki/hacktricks (tree) |
| 845 | macos-apple-events | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-apple-events> | ~ | HackTricks-wiki/hacktricks (tree) |
| 846 | macos-apple-scripts | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/macos-apple-scripts> | ~ | HackTricks-wiki/hacktricks (tree) |
| 847 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 848 | macos-tcc-credential-and-data-theft | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-credential-and-data-theft> | ~ | HackTricks-wiki/hacktricks (tree) |
| 849 | macos-tcc-payloads | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-payloads> | ~ | HackTricks-wiki/hacktricks (tree) |
| 850 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 851 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 852 | macos-users | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/macos-users> | ~ | HackTricks-wiki/hacktricks (tree) |
| 853 | README | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-security-and-privilege-escalation/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 854 | macos-useful-commands | <https://book.hacktricks.wiki/en/src/macos-hardening/macos-useful-commands> | ~ | HackTricks-wiki/hacktricks (tree) |
| 855 | abusing-android-media-pipelines-image-parsers | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/abusing-android-media-pipelines-image-parsers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 856 | accessibility-services-abuse | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/accessibility-services-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 857 | adb-commands | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/adb-commands> | ~ | HackTricks-wiki/hacktricks (tree) |
| 858 | android-anti-instrumentation-and-ssl-pinning-bypass | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 859 | android-application-level-virtualization | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-application-level-virtualization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 860 | android-applications-basics | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-applications-basics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 861 | android-enterprise-work-profile-bypass | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-enterprise-work-profile-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 862 | android-hce-nfc-emv-relay-attacks | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-hce-nfc-emv-relay-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 863 | android-physical-attacks | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-physical-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 864 | android-selinux-domains-and-policy-manipulation | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-selinux-domains-and-policy-manipulation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 865 | android-selinux-policy-analysis | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-selinux-policy-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 866 | android-task-hijacking | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-task-hijacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 867 | android-vpn-bypass | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/android-vpn-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 868 | apk-decompilers | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/apk-decompilers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 869 | avd-android-virtual-device | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/avd-android-virtual-device> | ~ | HackTricks-wiki/hacktricks (tree) |
| 870 | baseband-and-soc-isolation-exploitation | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/baseband-and-soc-isolation-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 871 | bypass-biometric-authentication-android | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/bypass-biometric-authentication-android> | ~ | HackTricks-wiki/hacktricks (tree) |
| 872 | content-protocol | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/content-protocol> | ~ | HackTricks-wiki/hacktricks (tree) |
| 873 | exploiting-content-providers | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/drozer-tutorial/exploiting-content-providers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 874 | README | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/drozer-tutorial/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 875 | exploiting-a-debuggeable-applciation | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/exploiting-a-debuggeable-applciation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 876 | firmware-level-zygote-backdoor-libandroid_runtime | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/firmware-level-zygote-backdoor-libandroid_runtime> | ~ | HackTricks-wiki/hacktricks (tree) |
| 877 | flutter | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/flutter> | ~ | HackTricks-wiki/hacktricks (tree) |
| 878 | frida-tutorial-1 | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/frida-tutorial/frida-tutorial-1> | ~ | HackTricks-wiki/hacktricks (tree) |
| 879 | frida-tutorial-2 | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/frida-tutorial/frida-tutorial-2> | ~ | HackTricks-wiki/hacktricks (tree) |
| 880 | objection-tutorial | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/frida-tutorial/objection-tutorial> | ~ | HackTricks-wiki/hacktricks (tree) |
| 881 | owaspuncrackable-1 | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/frida-tutorial/owaspuncrackable-1> | ~ | HackTricks-wiki/hacktricks (tree) |
| 882 | README | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/frida-tutorial/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 883 | in-memory-jni-shellcode-execution | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/in-memory-jni-shellcode-execution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 884 | inputmethodservice-ime-abuse | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/inputmethodservice-ime-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 885 | insecure-in-app-update-rce | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/insecure-in-app-update-rce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 886 | install-burp-certificate | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/install-burp-certificate> | ~ | HackTricks-wiki/hacktricks (tree) |
| 887 | intent-injection | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/intent-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 888 | make-apk-accept-ca-certificate | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/make-apk-accept-ca-certificate> | ~ | HackTricks-wiki/hacktricks (tree) |
| 889 | manual-deobfuscation | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/manual-deobfuscation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 890 | play-integrity-attestation-bypass | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/play-integrity-attestation-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 891 | react-native-application | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/react-native-application> | ~ | HackTricks-wiki/hacktricks (tree) |
| 892 | README | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 893 | reversing-native-libraries | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/reversing-native-libraries> | ~ | HackTricks-wiki/hacktricks (tree) |
| 894 | shizuku-privileged-api | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/shizuku-privileged-api> | ~ | HackTricks-wiki/hacktricks (tree) |
| 895 | smali-changes | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/smali-changes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 896 | spoofing-your-location-in-play-store | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/spoofing-your-location-in-play-store> | ~ | HackTricks-wiki/hacktricks (tree) |
| 897 | tapjacking | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/tapjacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 898 | telegram-mini-app-privacy-analysis | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/telegram-mini-app-privacy-analysis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 899 | webview-attacks | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-app-pentesting/webview-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 900 | android-checklist | <https://book.hacktricks.wiki/en/src/mobile-pentesting/android-checklist> | ~ | HackTricks-wiki/hacktricks (tree) |
| 901 | cordova-apps | <https://book.hacktricks.wiki/en/src/mobile-pentesting/cordova-apps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 902 | esim-javacard-exploitation | <https://book.hacktricks.wiki/en/src/mobile-pentesting/esim-javacard-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 903 | ios-pentesting-checklist | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting-checklist> | ~ | HackTricks-wiki/hacktricks (tree) |
| 904 | air-keyboard-remote-input-injection | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/air-keyboard-remote-input-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 905 | basic-ios-testing-operations | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/basic-ios-testing-operations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 906 | burp-configuration-for-ios | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/burp-configuration-for-ios> | ~ | HackTricks-wiki/hacktricks (tree) |
| 907 | extracting-entitlements-from-compiled-application | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/extracting-entitlements-from-compiled-application> | ~ | HackTricks-wiki/hacktricks (tree) |
| 908 | frida-configuration-in-ios | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/frida-configuration-in-ios> | ~ | HackTricks-wiki/hacktricks (tree) |
| 909 | ios-app-extensions | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-app-extensions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 910 | ios-basics | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-basics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 911 | ios-custom-uri-handlers-deeplinks-custom-schemes | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-custom-uri-handlers-deeplinks-custom-schemes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 912 | ios-hooking-with-objection | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-hooking-with-objection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 913 | ios-pentesting-without-jailbreak | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-pentesting-without-jailbreak> | ~ | HackTricks-wiki/hacktricks (tree) |
| 914 | ios-protocol-handlers | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-protocol-handlers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 915 | ios-serialisation-and-encoding | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-serialisation-and-encoding> | ~ | HackTricks-wiki/hacktricks (tree) |
| 916 | ios-testing-environment | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-testing-environment> | ~ | HackTricks-wiki/hacktricks (tree) |
| 917 | ios-uiactivity-sharing | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-uiactivity-sharing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 918 | ios-uipasteboard | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-uipasteboard> | ~ | HackTricks-wiki/hacktricks (tree) |
| 919 | ios-universal-links | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-universal-links> | ~ | HackTricks-wiki/hacktricks (tree) |
| 920 | ios-webviews | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/ios-webviews> | ~ | HackTricks-wiki/hacktricks (tree) |
| 921 | itunesstored-bookassetd-sandbox-escape | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/itunesstored-bookassetd-sandbox-escape> | ~ | HackTricks-wiki/hacktricks (tree) |
| 922 | README | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 923 | zero-click-messaging-image-parser-chains | <https://book.hacktricks.wiki/en/src/mobile-pentesting/ios-pentesting/zero-click-messaging-image-parser-chains> | ~ | HackTricks-wiki/hacktricks (tree) |
| 924 | xamarin-apps | <https://book.hacktricks.wiki/en/src/mobile-pentesting/xamarin-apps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 925 | 10000-network-data-management-protocol-ndmp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/10000-network-data-management-protocol-ndmp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 926 | 102-pentesting-iec-61850-mms | <https://book.hacktricks.wiki/en/src/network-services-pentesting/102-pentesting-iec-61850-mms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 927 | 1026-pentesting-rusersd | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1026-pentesting-rusersd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 928 | 1080-pentesting-socks | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1080-pentesting-socks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 929 | 1099-pentesting-java-rmi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1099-pentesting-java-rmi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 930 | memcache-commands | <https://book.hacktricks.wiki/en/src/network-services-pentesting/11211-memcache/memcache-commands> | ~ | HackTricks-wiki/hacktricks (tree) |
| 931 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/11211-memcache/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 932 | 113-pentesting-ident | <https://book.hacktricks.wiki/en/src/network-services-pentesting/113-pentesting-ident> | ~ | HackTricks-wiki/hacktricks (tree) |
| 933 | 12346-udp-pentesting-cisco-sd-wan-control-plane | <https://book.hacktricks.wiki/en/src/network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane> | ~ | HackTricks-wiki/hacktricks (tree) |
| 934 | 135-pentesting-msrpc | <https://book.hacktricks.wiki/en/src/network-services-pentesting/135-pentesting-msrpc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 935 | 137-138-139-pentesting-netbios | <https://book.hacktricks.wiki/en/src/network-services-pentesting/137-138-139-pentesting-netbios> | ~ | HackTricks-wiki/hacktricks (tree) |
| 936 | 1414-pentesting-ibmmq | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1414-pentesting-ibmmq> | ~ | HackTricks-wiki/hacktricks (tree) |
| 937 | 1521-1522-1529-pentesting-oracle-listener | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener> | ~ | HackTricks-wiki/hacktricks (tree) |
| 938 | 15672-pentesting-rabbitmq-management | <https://book.hacktricks.wiki/en/src/network-services-pentesting/15672-pentesting-rabbitmq-management> | ~ | HackTricks-wiki/hacktricks (tree) |
| 939 | 1723-pentesting-pptp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1723-pentesting-pptp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 940 | 1883-pentesting-mqtt-mosquitto | <https://book.hacktricks.wiki/en/src/network-services-pentesting/1883-pentesting-mqtt-mosquitto> | ~ | HackTricks-wiki/hacktricks (tree) |
| 941 | 20000-pentesting-dnp3 | <https://book.hacktricks.wiki/en/src/network-services-pentesting/20000-pentesting-dnp3> | ~ | HackTricks-wiki/hacktricks (tree) |
| 942 | 2375-pentesting-docker | <https://book.hacktricks.wiki/en/src/network-services-pentesting/2375-pentesting-docker> | ~ | HackTricks-wiki/hacktricks (tree) |
| 943 | 24007-24008-24009-49152-pentesting-glusterfs | <https://book.hacktricks.wiki/en/src/network-services-pentesting/24007-24008-24009-49152-pentesting-glusterfs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 944 | 2404-pentesting-iec-60870-5-104 | <https://book.hacktricks.wiki/en/src/network-services-pentesting/2404-pentesting-iec-60870-5-104> | ~ | HackTricks-wiki/hacktricks (tree) |
| 945 | 27017-27018-mongodb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/27017-27018-mongodb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 946 | 3128-pentesting-squid | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3128-pentesting-squid> | ~ | HackTricks-wiki/hacktricks (tree) |
| 947 | 32100-udp-pentesting-pppp-cs2-p2p-cameras | <https://book.hacktricks.wiki/en/src/network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras> | ~ | HackTricks-wiki/hacktricks (tree) |
| 948 | 3260-pentesting-iscsi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3260-pentesting-iscsi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 949 | 3299-pentesting-saprouter | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3299-pentesting-saprouter> | ~ | HackTricks-wiki/hacktricks (tree) |
| 950 | 3478-pentesting-turn | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3478-pentesting-turn> | ~ | HackTricks-wiki/hacktricks (tree) |
| 951 | 3632-pentesting-distcc | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3632-pentesting-distcc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 952 | 3690-pentesting-subversion-svn-server | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3690-pentesting-subversion-svn-server> | ~ | HackTricks-wiki/hacktricks (tree) |
| 953 | 3702-udp-pentesting-ws-discovery | <https://book.hacktricks.wiki/en/src/network-services-pentesting/3702-udp-pentesting-ws-discovery> | ~ | HackTricks-wiki/hacktricks (tree) |
| 954 | 4000-10080-pentesting-tidb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/4000-10080-pentesting-tidb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 955 | 4222-pentesting-nats | <https://book.hacktricks.wiki/en/src/network-services-pentesting/4222-pentesting-nats> | ~ | HackTricks-wiki/hacktricks (tree) |
| 956 | 43-pentesting-whois | <https://book.hacktricks.wiki/en/src/network-services-pentesting/43-pentesting-whois> | ~ | HackTricks-wiki/hacktricks (tree) |
| 957 | 4369-pentesting-erlang-port-mapper-daemon-epmd | <https://book.hacktricks.wiki/en/src/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 958 | 44134-pentesting-tiller-helm | <https://book.hacktricks.wiki/en/src/network-services-pentesting/44134-pentesting-tiller-helm> | ~ | HackTricks-wiki/hacktricks (tree) |
| 959 | 44818-ethernetip | <https://book.hacktricks.wiki/en/src/network-services-pentesting/44818-ethernetip> | ~ | HackTricks-wiki/hacktricks (tree) |
| 960 | 47808-udp-bacnet | <https://book.hacktricks.wiki/en/src/network-services-pentesting/47808-udp-bacnet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 961 | 4786-cisco-smart-install | <https://book.hacktricks.wiki/en/src/network-services-pentesting/4786-cisco-smart-install> | ~ | HackTricks-wiki/hacktricks (tree) |
| 962 | 4840-pentesting-opc-ua | <https://book.hacktricks.wiki/en/src/network-services-pentesting/4840-pentesting-opc-ua> | ~ | HackTricks-wiki/hacktricks (tree) |
| 963 | 49-pentesting-tacacs+ | <https://book.hacktricks.wiki/en/src/network-services-pentesting/49-pentesting-tacacs%2B> | ~ | HackTricks-wiki/hacktricks (tree) |
| 964 | 5000-pentesting-docker-registry | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5000-pentesting-docker-registry> | ~ | HackTricks-wiki/hacktricks (tree) |
| 965 | 50030-50060-50070-50075-50090-pentesting-hadoop | <https://book.hacktricks.wiki/en/src/network-services-pentesting/50030-50060-50070-50075-50090-pentesting-hadoop> | ~ | HackTricks-wiki/hacktricks (tree) |
| 966 | 512-pentesting-rexec | <https://book.hacktricks.wiki/en/src/network-services-pentesting/512-pentesting-rexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 967 | 515-pentesting-line-printer-daemon-lpd | <https://book.hacktricks.wiki/en/src/network-services-pentesting/515-pentesting-line-printer-daemon-lpd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 968 | 5353-udp-multicast-dns-mdns | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5353-udp-multicast-dns-mdns> | ~ | HackTricks-wiki/hacktricks (tree) |
| 969 | 5439-pentesting-redshift | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5439-pentesting-redshift> | ~ | HackTricks-wiki/hacktricks (tree) |
| 970 | 554-8554-pentesting-rtsp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/554-8554-pentesting-rtsp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 971 | 5555-android-debug-bridge | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5555-android-debug-bridge> | ~ | HackTricks-wiki/hacktricks (tree) |
| 972 | 55555-pentesting-solarwinds-arm | <https://book.hacktricks.wiki/en/src/network-services-pentesting/55555-pentesting-solarwinds-arm> | ~ | HackTricks-wiki/hacktricks (tree) |
| 973 | 5601-pentesting-kibana | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5601-pentesting-kibana> | ~ | HackTricks-wiki/hacktricks (tree) |
| 974 | 5671-5672-pentesting-amqp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5671-5672-pentesting-amqp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 975 | 584-pentesting-afp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/584-pentesting-afp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 976 | 5984-pentesting-couchdb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5984-pentesting-couchdb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 977 | 5985-5986-pentesting-omi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5985-5986-pentesting-omi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 978 | 5985-5986-pentesting-winrm | <https://book.hacktricks.wiki/en/src/network-services-pentesting/5985-5986-pentesting-winrm> | ~ | HackTricks-wiki/hacktricks (tree) |
| 979 | 6000-pentesting-x11 | <https://book.hacktricks.wiki/en/src/network-services-pentesting/6000-pentesting-x11> | ~ | HackTricks-wiki/hacktricks (tree) |
| 980 | 623-udp-ipmi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/623-udp-ipmi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 981 | 6379-pentesting-redis | <https://book.hacktricks.wiki/en/src/network-services-pentesting/6379-pentesting-redis> | ~ | HackTricks-wiki/hacktricks (tree) |
| 982 | 69-udp-tftp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/69-udp-tftp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 983 | 7-tcp-udp-pentesting-echo | <https://book.hacktricks.wiki/en/src/network-services-pentesting/7-tcp-udp-pentesting-echo> | ~ | HackTricks-wiki/hacktricks (tree) |
| 984 | 700-pentesting-epp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/700-pentesting-epp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 985 | 8009-pentesting-apache-jserv-protocol-ajp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/8009-pentesting-apache-jserv-protocol-ajp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 986 | 8086-pentesting-influxdb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/8086-pentesting-influxdb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 987 | 8089-splunkd | <https://book.hacktricks.wiki/en/src/network-services-pentesting/8089-splunkd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 988 | 8333-18333-38333-18444-pentesting-bitcoin | <https://book.hacktricks.wiki/en/src/network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin> | ~ | HackTricks-wiki/hacktricks (tree) |
| 989 | 873-pentesting-rsync | <https://book.hacktricks.wiki/en/src/network-services-pentesting/873-pentesting-rsync> | ~ | HackTricks-wiki/hacktricks (tree) |
| 990 | 9000-pentesting-fastcgi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/9000-pentesting-fastcgi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 991 | 9001-pentesting-hsqldb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/9001-pentesting-hsqldb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 992 | 9100-pjl | <https://book.hacktricks.wiki/en/src/network-services-pentesting/9100-pjl> | ~ | HackTricks-wiki/hacktricks (tree) |
| 993 | 9200-pentesting-elasticsearch | <https://book.hacktricks.wiki/en/src/network-services-pentesting/9200-pentesting-elasticsearch> | ~ | HackTricks-wiki/hacktricks (tree) |
| 994 | cassandra | <https://book.hacktricks.wiki/en/src/network-services-pentesting/cassandra> | ~ | HackTricks-wiki/hacktricks (tree) |
| 995 | ipsec-ike-vpn-pentesting | <https://book.hacktricks.wiki/en/src/network-services-pentesting/ipsec-ike-vpn-pentesting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 996 | nfs-service-pentesting | <https://book.hacktricks.wiki/en/src/network-services-pentesting/nfs-service-pentesting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 997 | pentesting-264-check-point-firewall-1 | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-264-check-point-firewall-1> | ~ | HackTricks-wiki/hacktricks (tree) |
| 998 | pentesting-631-internet-printing-protocol-ipp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-631-internet-printing-protocol-ipp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 999 | pentesting-compaq-hp-insight-manager | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-compaq-hp-insight-manager> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1000 | pentesting-dns | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-dns> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1001 | pentesting-finger | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-finger> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1002 | ftp-bounce-attack | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ftp/ftp-bounce-attack> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1003 | ftp-bounce-download-2oftp-file | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ftp/ftp-bounce-download-2oftp-file> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1004 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ftp/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1005 | pentesting-imap | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-imap> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1006 | pentesting-irc | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-irc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1007 | pentesting-iso-8583-payment-sockets | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-iso-8583-payment-sockets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1008 | pentesting-jdwp-java-debug-wire-protocol | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1009 | harvesting-tickets-from-linux | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1010 | harvesting-tickets-from-windows | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1011 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-kerberos-88/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1012 | pentesting-ldap | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ldap> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1013 | pentesting-modbus | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-modbus> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1014 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-mssql-microsoft-sql-server/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1015 | types-of-mssql-users | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-mssql-microsoft-sql-server/types-of-mssql-users> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1016 | pentesting-mysql | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-mysql> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1017 | pentesting-ntp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ntp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1018 | pentesting-pop | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-pop> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1019 | pentesting-postgresql | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-postgresql> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1020 | pentesting-profinet | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-profinet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1021 | pentesting-rdp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-rdp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1022 | pentesting-remote-gdbserver | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-remote-gdbserver> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1023 | pentesting-rlogin | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-rlogin> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1024 | pentesting-rpcbind | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-rpcbind> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1025 | pentesting-sap | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-sap> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1026 | ksmbd-attack-surface-and-fuzzing-syzkaller | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smb/ksmbd-attack-surface-and-fuzzing-syzkaller> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1027 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smb/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1028 | rpcclient-enumeration | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smb/rpcclient-enumeration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1029 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smtp/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1030 | smtp-commands | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smtp/smtp-commands> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1031 | smtp-smuggling | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-smtp/smtp-smuggling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1032 | cisco-snmp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-snmp/cisco-snmp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1033 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-snmp/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1034 | snmp-rce | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-snmp/snmp-rce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1035 | pentesting-ssh | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-ssh> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1036 | pentesting-telnet | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-telnet> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1037 | pentesting-veeam-backup-and-replication | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-veeam-backup-and-replication> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1038 | pentesting-vnc | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-vnc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1039 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-voip/basic-voip-protocols/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1040 | sip-session-initiation-protocol | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-voip/basic-voip-protocols/sip-session-initiation-protocol> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1041 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-voip/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1042 | adobe-coldfusion | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/adobe-coldfusion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1043 | aem-adobe-experience-cloud | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/aem-adobe-experience-cloud> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1044 | angular | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/angular> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1045 | apache | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/apache> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1046 | apache-tapestry | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/apache-tapestry> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1047 | artifactory-hacking-guide | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/artifactory-hacking-guide> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1048 | bolt-cms | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/bolt-cms> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1049 | firebase-database | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/buckets/firebase-database> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1050 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/buckets/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1051 | cgi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/cgi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1052 | citrix-netscaler | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/citrix-netscaler> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1053 | code-review-tools | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/code-review-tools> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1054 | custom-protocols | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/custom-protocols> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1055 | debug-and-admin-endpoints | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/debug-and-admin-endpoints> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1056 | django | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/django> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1057 | dotnet-soap-wsdl-client-exploitation | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/dotnet-soap-wsdl-client-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1058 | dotnetnuke-dnn | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/dotnetnuke-dnn> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1059 | drupal-rce | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/drupal/drupal-rce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1060 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/drupal/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1061 | electron-contextisolation-rce-via-electron-internal-code | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/electron-desktop-apps/electron-contextisolation-rce-via-electron-internal-code> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1062 | electron-contextisolation-rce-via-ipc | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/electron-desktop-apps/electron-contextisolation-rce-via-ipc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1063 | electron-contextisolation-rce-via-preload-code | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/electron-desktop-apps/electron-contextisolation-rce-via-preload-code> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1064 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/electron-desktop-apps/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1065 | flask | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/flask> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1066 | fortinet-fortiweb | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/fortinet-fortiweb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1067 | geonetwork | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/geonetwork> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1068 | git | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/git> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1069 | golang | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/golang> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1070 | grafana | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/grafana> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1071 | graphql | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/graphql> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1072 | h2-java-sql-database | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/h2-java-sql-database> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1073 | iis-internet-information-services | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/iis-internet-information-services> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1074 | imagemagick-security | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/imagemagick-security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1075 | ispconfig | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/ispconfig> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1076 | java-servlet-filter-memory-shells | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/java-servlet-filter-memory-shells> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1077 | jboss | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/jboss> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1078 | jira | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/jira> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1079 | joomla | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/joomla> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1080 | jsp | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/jsp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1081 | laravel | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/laravel> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1082 | meshcentral | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/meshcentral> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1083 | microsoft-sharepoint | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/microsoft-sharepoint> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1084 | moodle | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/moodle> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1085 | nextjs | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/nextjs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1086 | nginx | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/nginx> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1087 | nodejs-express | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/nodejs-express> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1088 | perl-tricks | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/perl-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1089 | php-rce-abusing-object-creation-new-usd_get-a-usd_get-b | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-rce-abusing-object-creation-new-usd_get-a-usd_get-b> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1090 | php-ssrf | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-ssrf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1091 | disable_functions-bypass-dl-function | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-dl-function> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1092 | disable_functions-bypass-imagick-less-than-3.3.0-php-greater-than-5.4-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-imagick-less-than-3.3.0-php-greater-than-5.4-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1093 | disable_functions-bypass-mod_cgi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-mod_cgi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1094 | disable_functions-bypass-php-4-greater-than-4.2.0-php-5-pcntl_exec | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-4-greater-than-4.2.0-php-5-pcntl_exec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1095 | disable_functions-bypass-php-5.2-fopen-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-5.2-fopen-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1096 | disable_functions-bypass-php-5.2.3-win32std-ext-protections-bypass | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-5.2.3-win32std-ext-protections-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1097 | disable_functions-bypass-php-5.2.4-and-5.2.5-php-curl | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-5.2.4-and-5.2.5-php-curl> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1098 | disable_functions-bypass-php-7.0-7.4-nix-only | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-7.0-7.4-nix-only> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1099 | disable_functions-bypass-php-fpm-fastcgi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1100 | disable_functions-bypass-php-less-than-5.2.9-on-windows | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-less-than-5.2.9-on-windows> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1101 | disable_functions-bypass-php-perl-extension-safe_mode-bypass-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-perl-extension-safe_mode-bypass-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1102 | disable_functions-bypass-php-safe_mode-bypass-via-proc_open-and-custom-environment-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-safe_mode-bypass-via-proc_open-and-custom-environment-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1103 | disable_functions-bypass-via-mem | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-via-mem> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1104 | disable_functions-php-5.2.4-ioncube-extension-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-php-5.2.4-ioncube-extension-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1105 | disable_functions-php-5.x-shellshock-exploit | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-php-5.x-shellshock-exploit> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1106 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1107 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/php-tricks-esp/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1108 | prestashop | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/prestashop> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1109 | proxmox-ve | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/proxmox-ve> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1110 | put-method-webdav | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/put-method-webdav> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1111 | python | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/python> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1112 | react | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/react> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1113 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1114 | rocket-chat | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/rocket-chat> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1115 | roundcube | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/roundcube> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1116 | ruby-tricks | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/ruby-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1117 | salesforce | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/salesforce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1118 | servicenow | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/servicenow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1119 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/sitecore/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1120 | spring-actuators | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/spring-actuators> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1121 | spring-data-binding-classloader-manipulation | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/spring-data-binding-classloader-manipulation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1122 | ssr-meta-frameworks | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/ssr-meta-frameworks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1123 | supabase-postgrest | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/supabase-postgrest> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1124 | swagger-openapi-ui | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/swagger-openapi-ui> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1125 | symphony | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/symphony> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1126 | telerik-ui-aspnet-ajax-unsafe-reflection-webresource-axd | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/telerik-ui-aspnet-ajax-unsafe-reflection-webresource-axd> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1127 | README | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/tomcat/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1128 | traefik | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/traefik> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1129 | uncovering-cloudflare | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/uncovering-cloudflare> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1130 | veeam-service-provider-console | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/veeam-service-provider-console> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1131 | vmware-esx-vcenter... | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/vmware-esx-vcenter...> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1132 | vuejs | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/vuejs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1133 | werkzeug | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/werkzeug> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1134 | wordpress | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/wordpress> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1135 | wsgi | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/wsgi> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1136 | zabbix | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/zabbix> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1137 | zoneminder-motioneye-motion | <https://book.hacktricks.wiki/en/src/network-services-pentesting/pentesting-web/zoneminder-motioneye-motion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1138 | 2fa-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/2fa-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1139 | 403-and-401-bypasses | <https://book.hacktricks.wiki/en/src/pentesting-web/403-and-401-bypasses> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1140 | abusing-hop-by-hop-headers | <https://book.hacktricks.wiki/en/src/pentesting-web/abusing-hop-by-hop-headers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1141 | account-takeover | <https://book.hacktricks.wiki/en/src/pentesting-web/account-takeover> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1142 | application-layer-dos | <https://book.hacktricks.wiki/en/src/pentesting-web/application-layer-dos> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1143 | browext-clickjacking | <https://book.hacktricks.wiki/en/src/pentesting-web/browser-extension-pentesting-methodology/browext-clickjacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1144 | browext-permissions-and-host_permissions | <https://book.hacktricks.wiki/en/src/pentesting-web/browser-extension-pentesting-methodology/browext-permissions-and-host_permissions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1145 | browext-xss-example | <https://book.hacktricks.wiki/en/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1146 | forced-extension-load-preferences-mac-forgery-windows | <https://book.hacktricks.wiki/en/src/pentesting-web/browser-extension-pentesting-methodology/forced-extension-load-preferences-mac-forgery-windows> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1147 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/browser-extension-pentesting-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1148 | burp-suite | <https://book.hacktricks.wiki/en/src/pentesting-web/burp-suite> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1149 | business-logic-vulnerabilities | <https://book.hacktricks.wiki/en/src/pentesting-web/business-logic-vulnerabilities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1150 | bypass-payment-process | <https://book.hacktricks.wiki/en/src/pentesting-web/bypass-payment-process> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1151 | cache-poisoning-to-dos | <https://book.hacktricks.wiki/en/src/pentesting-web/cache-deception/cache-poisoning-to-dos> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1152 | cache-poisoning-via-url-discrepancies | <https://book.hacktricks.wiki/en/src/pentesting-web/cache-deception/cache-poisoning-via-url-discrepancies> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1153 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/cache-deception/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1154 | captcha-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/captcha-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1155 | clickjacking | <https://book.hacktricks.wiki/en/src/pentesting-web/clickjacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1156 | client-side-path-traversal | <https://book.hacktricks.wiki/en/src/pentesting-web/client-side-path-traversal> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1157 | client-side-template-injection-csti | <https://book.hacktricks.wiki/en/src/pentesting-web/client-side-template-injection-csti> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1158 | command-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/command-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1159 | commons-text-string-interpolation | <https://book.hacktricks.wiki/en/src/pentesting-web/commons-text-string-interpolation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1160 | csp-bypass-self-+-unsafe-inline-with-iframes | <https://book.hacktricks.wiki/en/src/pentesting-web/content-security-policy-csp-bypass/csp-bypass-self-%2B-unsafe-inline-with-iframes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1161 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/content-security-policy-csp-bypass/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1162 | content-spoofing-text-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/content-spoofing-text-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1163 | cors-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/cors-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1164 | crlf-0d-0a | <https://book.hacktricks.wiki/en/src/pentesting-web/crlf-0d-0a> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1165 | csrf-cross-site-request-forgery | <https://book.hacktricks.wiki/en/src/pentesting-web/csrf-cross-site-request-forgery> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1166 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/dangling-markup-html-scriptless-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1167 | ss-leaks | <https://book.hacktricks.wiki/en/src/pentesting-web/dangling-markup-html-scriptless-injection/ss-leaks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1168 | dapps-DecentralizedApplications | <https://book.hacktricks.wiki/en/src/pentesting-web/dapps-DecentralizedApplications> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1169 | dependency-confusion | <https://book.hacktricks.wiki/en/src/pentesting-web/dependency-confusion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1170 | basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1171 | basic-java-deserialization-objectinputstream-readobject | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/basic-java-deserialization-objectinputstream-readobject> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1172 | exploiting-__viewstate-knowing-the-secret | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/exploiting-__viewstate-knowing-the-secret> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1173 | exploiting-__viewstate-parameter | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/exploiting-__viewstate-parameter> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1174 | java-apache-shiro-rememberme | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-apache-shiro-rememberme> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1175 | java-dns-deserialization-and-gadgetprobe | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-dns-deserialization-and-gadgetprobe> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1176 | java-hessian-burlap-amf-deserialization | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-hessian-burlap-amf-deserialization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1177 | java-jsf-viewstate-.faces-deserialization | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-jsf-viewstate-.faces-deserialization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1178 | java-signedobject-gated-deserialization | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-signedobject-gated-deserialization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1179 | java-transformers-to-rutime-exec-payload | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/java-transformers-to-rutime-exec-payload> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1180 | jndi-java-naming-and-directory-interface-and-log4shell | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1181 | livewire-hydration-synthesizer-abuse | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/livewire-hydration-synthesizer-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1182 | client-side-prototype-pollution | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1183 | express-prototype-pollution-gadgets | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1184 | prototype-pollution-to-rce | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1185 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/nodejs-proto-prototype-pollution/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1186 | php-deserialization-+-autoload-classes | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/php-deserialization-%2B-autoload-classes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1187 | python-yaml-deserialization | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/python-yaml-deserialization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1188 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1189 | ruby-_json-pollution | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/ruby-_json-pollution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1190 | ruby-class-pollution | <https://book.hacktricks.wiki/en/src/pentesting-web/deserialization/ruby-class-pollution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1191 | domain-subdomain-takeover | <https://book.hacktricks.wiki/en/src/pentesting-web/domain-subdomain-takeover> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1192 | email-injections | <https://book.hacktricks.wiki/en/src/pentesting-web/email-injections> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1193 | lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-%2B-php_stream_prefer_studio-%2B-path-disclosure> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1194 | lfi2rce-via-eternal-waiting | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1195 | lfi2rce-via-nginx-temp-files | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1196 | lfi2rce-via-php-filters | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-php-filters> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1197 | lfi2rce-via-phpinfo | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-phpinfo> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1198 | lfi2rce-via-temp-file-uploads | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1199 | phar-deserialization | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/phar-deserialization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1200 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1201 | via-php_session_upload_progress | <https://book.hacktricks.wiki/en/src/pentesting-web/file-inclusion/via-php_session_upload_progress> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1202 | pdf-upload-xxe-and-cors-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1203 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/file-upload/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1204 | formula-csv-doc-latex-ghostscript-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/formula-csv-doc-latex-ghostscript-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1205 | grpc-web-pentest | <https://book.hacktricks.wiki/en/src/pentesting-web/grpc-web-pentest> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1206 | h2c-smuggling | <https://book.hacktricks.wiki/en/src/pentesting-web/h2c-smuggling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1207 | hacking-jwt-json-web-tokens | <https://book.hacktricks.wiki/en/src/pentesting-web/hacking-jwt-json-web-tokens> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1208 | cookie-bomb | <https://book.hacktricks.wiki/en/src/pentesting-web/hacking-with-cookies/cookie-bomb> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1209 | cookie-jar-overflow | <https://book.hacktricks.wiki/en/src/pentesting-web/hacking-with-cookies/cookie-jar-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1210 | cookie-tossing | <https://book.hacktricks.wiki/en/src/pentesting-web/hacking-with-cookies/cookie-tossing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1211 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/hacking-with-cookies/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1212 | http-connection-contamination | <https://book.hacktricks.wiki/en/src/pentesting-web/http-connection-contamination> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1213 | http-connection-request-smuggling | <https://book.hacktricks.wiki/en/src/pentesting-web/http-connection-request-smuggling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1214 | browser-http-request-smuggling | <https://book.hacktricks.wiki/en/src/pentesting-web/http-request-smuggling/browser-http-request-smuggling> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1215 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/http-request-smuggling/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1216 | request-smuggling-in-http-2-downgrades | <https://book.hacktricks.wiki/en/src/pentesting-web/http-request-smuggling/request-smuggling-in-http-2-downgrades> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1217 | http-response-smuggling-desync | <https://book.hacktricks.wiki/en/src/pentesting-web/http-response-smuggling-desync> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1218 | http2-protocol-dos | <https://book.hacktricks.wiki/en/src/pentesting-web/http2-protocol-dos> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1219 | idor | <https://book.hacktricks.wiki/en/src/pentesting-web/idor> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1220 | iframe-traps | <https://book.hacktricks.wiki/en/src/pentesting-web/iframe-traps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1221 | json-xml-yaml-hacking | <https://book.hacktricks.wiki/en/src/pentesting-web/json-xml-yaml-hacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1222 | ldap-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/ldap-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1223 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/login-bypass/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1224 | sql-login-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/login-bypass/sql-login-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1225 | mass-assignment-cwe-915 | <https://book.hacktricks.wiki/en/src/pentesting-web/mass-assignment-cwe-915> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1226 | nosql-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/nosql-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1227 | oauth-to-account-takeover | <https://book.hacktricks.wiki/en/src/pentesting-web/oauth-to-account-takeover> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1228 | open-redirect | <https://book.hacktricks.wiki/en/src/pentesting-web/open-redirect> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1229 | orm-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/orm-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1230 | parameter-pollution | <https://book.hacktricks.wiki/en/src/pentesting-web/parameter-pollution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1231 | phone-number-injections | <https://book.hacktricks.wiki/en/src/pentesting-web/phone-number-injections> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1232 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/pocs-and-polygloths-cheatsheet/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1233 | web-vulns-list | <https://book.hacktricks.wiki/en/src/pentesting-web/pocs-and-polygloths-cheatsheet/web-vulns-list> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1234 | blocking-main-page-to-steal-postmessage | <https://book.hacktricks.wiki/en/src/pentesting-web/postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1235 | bypassing-sop-with-iframes-1 | <https://book.hacktricks.wiki/en/src/pentesting-web/postmessage-vulnerabilities/bypassing-sop-with-iframes-1> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1236 | bypassing-sop-with-iframes-2 | <https://book.hacktricks.wiki/en/src/pentesting-web/postmessage-vulnerabilities/bypassing-sop-with-iframes-2> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1237 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/postmessage-vulnerabilities/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1238 | steal-postmessage-modifying-iframe-location | <https://book.hacktricks.wiki/en/src/pentesting-web/postmessage-vulnerabilities/steal-postmessage-modifying-iframe-location> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1239 | proxy-waf-protections-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/proxy-waf-protections-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1240 | race-condition | <https://book.hacktricks.wiki/en/src/pentesting-web/race-condition> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1241 | rate-limit-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/rate-limit-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1242 | referer-header-and-referrer-policy | <https://book.hacktricks.wiki/en/src/pentesting-web/referer-header-and-referrer-policy> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1243 | reflected-file-download | <https://book.hacktricks.wiki/en/src/pentesting-web/reflected-file-download> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1244 | registration-vulnerabilities | <https://book.hacktricks.wiki/en/src/pentesting-web/registration-vulnerabilities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1245 | regular-expression-denial-of-service-redos | <https://book.hacktricks.wiki/en/src/pentesting-web/regular-expression-denial-of-service-redos> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1246 | reset-password | <https://book.hacktricks.wiki/en/src/pentesting-web/reset-password> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1247 | reverse-tab-nabbing | <https://book.hacktricks.wiki/en/src/pentesting-web/reverse-tab-nabbing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1248 | rsql-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/rsql-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1249 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/saml-attacks/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1250 | saml-basics | <https://book.hacktricks.wiki/en/src/pentesting-web/saml-attacks/saml-basics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1251 | sensitive-information-exfiltration | <https://book.hacktricks.wiki/en/src/pentesting-web/sensitive-information-exfiltration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1252 | server-side-inclusion-edge-side-inclusion-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/server-side-inclusion-edge-side-inclusion-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1253 | server-side-javascript-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/server-side-javascript-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1254 | soap-jax-ws-threadlocal-auth-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/soap-jax-ws-threadlocal-auth-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1255 | special-http-headers | <https://book.hacktricks.wiki/en/src/pentesting-web/special-http-headers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1256 | cypher-injection-neo4j | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/cypher-injection-neo4j> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1257 | hql-jpql-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/hql-jpql-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1258 | ms-access-sql-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/ms-access-sql-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1259 | mssql-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/mssql-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1260 | mysql-ssrf | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/mysql-injection/mysql-ssrf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1261 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/mysql-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1262 | oracle-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/oracle-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1263 | big-binary-files-upload-postgresql | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/big-binary-files-upload-postgresql> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1264 | dblink-lo_import-data-exfiltration | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/dblink-lo_import-data-exfiltration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1265 | network-privesc-port-scanner-and-ntlm-chanllenge-response-disclosure | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/network-privesc-port-scanner-and-ntlm-chanllenge-response-disclosure> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1266 | pl-pgsql-password-bruteforce | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/pl-pgsql-password-bruteforce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1267 | rce-with-postgresql-extensions | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1268 | rce-with-postgresql-languages | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-languages> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1269 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/postgresql-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1270 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1271 | sqlite-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/sqlite-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1272 | sqlmap | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/sqlmap> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1273 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/sqlmap/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1274 | second-order-injection-sqlmap | <https://book.hacktricks.wiki/en/src/pentesting-web/sql-injection/sqlmap/second-order-injection-sqlmap> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1275 | cloud-ssrf | <https://book.hacktricks.wiki/en/src/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1276 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/ssrf-server-side-request-forgery/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1277 | url-format-bypass | <https://book.hacktricks.wiki/en/src/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1278 | el-expression-language | <https://book.hacktricks.wiki/en/src/pentesting-web/ssti-server-side-template-injection/el-expression-language> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1279 | jinja2-ssti | <https://book.hacktricks.wiki/en/src/pentesting-web/ssti-server-side-template-injection/jinja2-ssti> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1280 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/ssti-server-side-template-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1281 | timing-attacks | <https://book.hacktricks.wiki/en/src/pentesting-web/timing-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1282 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/unicode-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1283 | unicode-normalization | <https://book.hacktricks.wiki/en/src/pentesting-web/unicode-injection/unicode-normalization> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1284 | uuid-insecurities | <https://book.hacktricks.wiki/en/src/pentesting-web/uuid-insecurities> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1285 | web-api-pentesting | <https://book.hacktricks.wiki/en/src/pentesting-web/web-api-pentesting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1286 | web-tool-wfuzz | <https://book.hacktricks.wiki/en/src/pentesting-web/web-tool-wfuzz> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1287 | web-vulnerabilities-methodology | <https://book.hacktricks.wiki/en/src/pentesting-web/web-vulnerabilities-methodology> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1288 | webhook-security | <https://book.hacktricks.wiki/en/src/pentesting-web/webhook-security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1289 | websocket-attacks | <https://book.hacktricks.wiki/en/src/pentesting-web/websocket-attacks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1290 | xml-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/xml-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1291 | xpath-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/xpath-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1292 | connection-pool-by-destination-example | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/connection-pool-by-destination-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1293 | connection-pool-example | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/connection-pool-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1294 | cookie-bomb-+-onerror-xs-leak | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/cookie-bomb-%2B-onerror-xs-leak> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1295 | css-injection-code | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/css-injection/css-injection-code> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1296 | less-code-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/css-injection/less-code-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1297 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/css-injection/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1298 | event-loop-blocking-+-lazy-images | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/event-loop-blocking-%2B-lazy-images> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1299 | javascript-execution-xs-leak | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/javascript-execution-xs-leak> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1300 | performance.now-+-force-heavy-task | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/performance.now-%2B-force-heavy-task> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1301 | performance.now-example | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/performance.now-example> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1302 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1303 | url-max-length-client-side | <https://book.hacktricks.wiki/en/src/pentesting-web/xs-search/url-max-length-client-side> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1304 | xslt-server-side-injection-extensible-stylesheet-language-transformations | <https://book.hacktricks.wiki/en/src/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1305 | abusing-service-workers | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1306 | chrome-cache-to-xss | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1307 | debugging-client-side-js | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/debugging-client-side-js> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1308 | dom-clobbering | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/dom-clobbering> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1309 | dom-invader | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/dom-invader> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1310 | dom-xss | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/dom-xss> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1311 | iframes-in-xss-and-csp | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1312 | integer-overflow | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/integer-overflow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1313 | js-hoisting | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/js-hoisting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1314 | other-js-tricks | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/other-js-tricks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1315 | pdf-injection | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/pdf-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1316 | README | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1317 | server-side-xss-dynamic-pdf | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1318 | shadow-dom | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/shadow-dom> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1319 | sniff-leak | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/sniff-leak> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1320 | some-same-origin-method-execution | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/some-same-origin-method-execution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1321 | steal-info-js | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/steal-info-js> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1322 | wasm-linear-memory-template-overwrite-xss | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/wasm-linear-memory-template-overwrite-xss> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1323 | xss-in-markdown | <https://book.hacktricks.wiki/en/src/pentesting-web/xss-cross-site-scripting/xss-in-markdown> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1324 | xssi-cross-site-script-inclusion | <https://book.hacktricks.wiki/en/src/pentesting-web/xssi-cross-site-script-inclusion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1325 | xxe-xee-xml-external-entity | <https://book.hacktricks.wiki/en/src/pentesting-web/xxe-xee-xml-external-entity> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1326 | advanced-network-privacy-architectures | <https://book.hacktricks.wiki/en/src/privacy/advanced-network-privacy-architectures> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1327 | anonymous-internet-access-techniques | <https://book.hacktricks.wiki/en/src/privacy/anonymous-internet-access-techniques> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1328 | anonymous-payment-techniques | <https://book.hacktricks.wiki/en/src/privacy/anonymous-payment-techniques> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1329 | attribution-detection-and-countermeasures | <https://book.hacktricks.wiki/en/src/privacy/attribution-detection-and-countermeasures> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1330 | authorized-adversary-emulation-labs | <https://book.hacktricks.wiki/en/src/privacy/authorized-adversary-emulation-labs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1331 | authorized-red-team-infrastructure | <https://book.hacktricks.wiki/en/src/privacy/authorized-red-team-infrastructure> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1332 | capture-resilient-authorized-field-nodes | <https://book.hacktricks.wiki/en/src/privacy/capture-resilient-authorized-field-nodes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1333 | covert-physical-wireless-access | <https://book.hacktricks.wiki/en/src/privacy/covert-physical-wireless-access> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1334 | cryptocurrency-privacy | <https://book.hacktricks.wiki/en/src/privacy/cryptocurrency-privacy> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1335 | financial-obfuscation-tradecraft | <https://book.hacktricks.wiki/en/src/privacy/financial-obfuscation-tradecraft> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1336 | government-and-apt-case-studies | <https://book.hacktricks.wiki/en/src/privacy/government-and-apt-case-studies> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1337 | network-privacy-and-anonymous-connectivity | <https://book.hacktricks.wiki/en/src/privacy/network-privacy-and-anonymous-connectivity> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1338 | offensive-infrastructure-and-attribution-evasion | <https://book.hacktricks.wiki/en/src/privacy/offensive-infrastructure-and-attribution-evasion> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1339 | operational-privacy-playbooks | <https://book.hacktricks.wiki/en/src/privacy/operational-privacy-playbooks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1340 | privacy-operating-systems | <https://book.hacktricks.wiki/en/src/privacy/privacy-operating-systems> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1341 | privacy-preserving-communications-and-sharing | <https://book.hacktricks.wiki/en/src/privacy/privacy-preserving-communications-and-sharing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1342 | privacy-preserving-payment-protocols | <https://book.hacktricks.wiki/en/src/privacy/privacy-preserving-payment-protocols> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1343 | private-digital-payments | <https://book.hacktricks.wiki/en/src/privacy/private-digital-payments> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1344 | README | <https://book.hacktricks.wiki/en/src/privacy/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1345 | reproducible-privacy-testing | <https://book.hacktricks.wiki/en/src/privacy/reproducible-privacy-testing> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1346 | threat-modeling-and-identity-separation | <https://book.hacktricks.wiki/en/src/privacy/threat-modeling-and-identity-separation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1347 | README | <https://book.hacktricks.wiki/en/src/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1348 | common-api-used-in-malware | <https://book.hacktricks.wiki/en/src/reversing/common-api-used-in-malware> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1349 | angr-examples | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/angr/angr-examples> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1350 | README | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/angr/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1351 | blobrunner | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/blobrunner> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1352 | cheat-engine | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/cheat-engine> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1353 | nodejs-v8-cached-bytecode | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/nodejs-v8-cached-bytecode> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1354 | README | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1355 | satisfiability-modulo-theories-smt-z3 | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/satisfiability-modulo-theories-smt-z3> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1356 | windbg-automation | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/windbg-automation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1357 | windows-kernel-debugging-kernelflirt | <https://book.hacktricks.wiki/en/src/reversing/reversing-tools-basic-methods/windows-kernel-debugging-kernelflirt> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1358 | windows-exception-driven-control-flow | <https://book.hacktricks.wiki/en/src/reversing/windows-exception-driven-control-flow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1359 | word-macros | <https://book.hacktricks.wiki/en/src/reversing/word-macros> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1360 | README | <https://book.hacktricks.wiki/en/src/stego/audio/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1361 | README | <https://book.hacktricks.wiki/en/src/stego/documents/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1362 | README | <https://book.hacktricks.wiki/en/src/stego/images/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1363 | README | <https://book.hacktricks.wiki/en/src/stego/malware-and-network/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1364 | README | <https://book.hacktricks.wiki/en/src/stego/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1365 | README | <https://book.hacktricks.wiki/en/src/stego/text/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1366 | README | <https://book.hacktricks.wiki/en/src/stego/workflow/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1367 | SUMMARY | <https://book.hacktricks.wiki/en/src/SUMMARY> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1368 | more-tools | <https://book.hacktricks.wiki/en/src/todo/more-tools> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1369 | about-the-author | <https://book.hacktricks.wiki/en/src/welcome/about-the-author> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1370 | cookies-policy | <https://book.hacktricks.wiki/en/src/welcome/cookies-policy> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1371 | hacktricks-values-and-faq | <https://book.hacktricks.wiki/en/src/welcome/hacktricks-values-and-faq> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1372 | abusing-ad-mssql | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/abusing-ad-mssql> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1373 | BadSuccessor | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/acl-persistence-abuse/BadSuccessor> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1374 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/acl-persistence-abuse/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1375 | shadow-credentials | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1376 | ad-certificates | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1377 | account-persistence | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates/account-persistence> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1378 | certificate-theft | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates/certificate-theft> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1379 | domain-escalation | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1380 | domain-persistence | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates/domain-persistence> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1381 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-certificates/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1382 | ad-dns-records | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-dns-records> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1383 | ad-dynamic-objects-anti-forensics | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-dynamic-objects-anti-forensics> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1384 | ad-information-in-printers | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ad-information-in-printers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1385 | adws-enumeration | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/adws-enumeration> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1386 | asreproast | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/asreproast> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1387 | badsuccessor-dmsa-migration-abuse | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/badsuccessor-dmsa-migration-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1388 | bloodhound | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/bloodhound> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1389 | constrained-delegation | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/constrained-delegation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1390 | custom-ssp | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/custom-ssp> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1391 | dcshadow | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/dcshadow> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1392 | dcsync | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/dcsync> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1393 | diamond-ticket | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/diamond-ticket> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1394 | dsrm-credentials | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/dsrm-credentials> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1395 | external-forest-domain-one-way-outbound | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/external-forest-domain-one-way-outbound> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1396 | external-forest-domain-oneway-inbound | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/external-forest-domain-oneway-inbound> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1397 | golden-dmsa-gmsa | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/golden-dmsa-gmsa> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1398 | golden-ticket | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/golden-ticket> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1399 | kerberoast | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/kerberoast> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1400 | kerberos-authentication | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/kerberos-authentication> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1401 | kerberos-double-hop-problem | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/kerberos-double-hop-problem> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1402 | lansweeper-security | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/lansweeper-security> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1403 | laps | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/laps> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1404 | ldap-signing-and-channel-binding | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/ldap-signing-and-channel-binding> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1405 | over-pass-the-hash-pass-the-key | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1406 | pass-the-ticket | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/pass-the-ticket> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1407 | password-spraying | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/password-spraying> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1408 | printers-spooler-service-abuse | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/printers-spooler-service-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1409 | printnightmare | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/printnightmare> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1410 | privileged-groups-and-token-privileges | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1411 | rdp-sessions-abuse | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/rdp-sessions-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1412 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1413 | resource-based-constrained-delegation | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/resource-based-constrained-delegation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1414 | sccm-management-point-relay-sql-policy-secrets | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/sccm-management-point-relay-sql-policy-secrets> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1415 | security-descriptors | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/security-descriptors> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1416 | sid-history-injection | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/sid-history-injection> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1417 | silver-ticket | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/silver-ticket> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1418 | skeleton-key | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/skeleton-key> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1419 | TimeRoasting | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/TimeRoasting> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1420 | unconstrained-delegation | <https://book.hacktricks.wiki/en/src/windows-hardening/active-directory-methodology/unconstrained-delegation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1421 | authentication-credentials-uac-and-efs | <https://book.hacktricks.wiki/en/src/windows-hardening/authentication-credentials-uac-and-efs> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1422 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/authentication-credentials-uac-and-efs/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1423 | uac-user-account-control | <https://book.hacktricks.wiki/en/src/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1424 | av-bypass | <https://book.hacktricks.wiki/en/src/windows-hardening/av-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1425 | basic-cmd-for-pentesters | <https://book.hacktricks.wiki/en/src/windows-hardening/basic-cmd-for-pentesters> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1426 | powerview | <https://book.hacktricks.wiki/en/src/windows-hardening/basic-powershell-for-pentesters/powerview> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1427 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/basic-powershell-for-pentesters/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1428 | checklist-windows-privilege-escalation | <https://book.hacktricks.wiki/en/src/windows-hardening/checklist-windows-privilege-escalation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1429 | cobalt-strike | <https://book.hacktricks.wiki/en/src/windows-hardening/cobalt-strike> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1430 | atexec | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/atexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1431 | dcomexec | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/dcomexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1432 | psexec-and-winexec | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/psexec-and-winexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1433 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1434 | winrm | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/winrm> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1435 | wmiexec | <https://book.hacktricks.wiki/en/src/windows-hardening/lateral-movement/wmiexec> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1436 | mythic | <https://book.hacktricks.wiki/en/src/windows-hardening/mythic> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1437 | places-to-steal-ntlm-creds | <https://book.hacktricks.wiki/en/src/windows-hardening/ntlm/places-to-steal-ntlm-creds> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1438 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/ntlm/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1439 | protocol-handler-shell-execute-abuse | <https://book.hacktricks.wiki/en/src/windows-hardening/protocol-handler-shell-execute-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1440 | credentials-mimikatz | <https://book.hacktricks.wiki/en/src/windows-hardening/stealing-credentials/credentials-mimikatz> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1441 | credentials-protections | <https://book.hacktricks.wiki/en/src/windows-hardening/stealing-credentials/credentials-protections> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1442 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/stealing-credentials/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1443 | wts-impersonator | <https://book.hacktricks.wiki/en/src/windows-hardening/stealing-credentials/wts-impersonator> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1444 | virtualized-payload-execution | <https://book.hacktricks.wiki/en/src/windows-hardening/virtualized-payload-execution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1445 | visual-studio-project-msbuild-execution | <https://book.hacktricks.wiki/en/src/windows-hardening/visual-studio-project-msbuild-execution> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1446 | visual-studio-vsix-extension-abuse | <https://book.hacktricks.wiki/en/src/windows-hardening/visual-studio-vsix-extension-abuse> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1447 | abusing-auto-updaters-and-ipc | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/abusing-auto-updaters-and-ipc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1448 | access-tokens | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/access-tokens> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1449 | acls-dacls-sacls-aces | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/acls-dacls-sacls-aces> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1450 | appenddata-addsubdirectory-permission-over-service-registry | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1451 | arbitrary-kernel-rw-token-theft | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1452 | cloud-files-placeholder-name-toctou | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/cloud-files-placeholder-name-toctou> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1453 | com-hijacking | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/com-hijacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1454 | create-msi-with-wix | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/create-msi-with-wix> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1455 | advanced-html-staged-dll-sideloading | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/advanced-html-staged-dll-sideloading> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1456 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1457 | windows-cpython-build-landmark-sys-path-hijacking | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/windows-cpython-build-landmark-sys-path-hijacking> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1458 | writable-sys-path-dll-hijacking-privesc | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1459 | dpapi-extracting-passwords | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1460 | from-high-integrity-to-system-with-name-pipes | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/from-high-integrity-to-system-with-name-pipes> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1461 | integrity-levels | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/integrity-levels> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1462 | juicypotato | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/juicypotato> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1463 | kernel-mode-file-access-check-bypass | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/kernel-mode-file-access-check-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1464 | kernel-race-condition-object-manager-slowdown | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/kernel-race-condition-object-manager-slowdown> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1465 | leaked-handle-exploitation | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/leaked-handle-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1466 | local-ntlm-reflection-via-smb-arbitrary-port | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1467 | msi-wrapper | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/msi-wrapper> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1468 | named-pipe-client-impersonation | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1469 | notepad-plus-plus-plugin-autoload-persistence | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1470 | privilege-escalation-abusing-tokens | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1471 | privilege-escalation-with-autorun-binaries | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1472 | README | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/README> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1473 | roguepotato-and-printspoofer | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1474 | secure-desktop-accessibility-registry-propagation-regpwn | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1475 | sedebug-+-seimpersonate-copy-token | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/sedebug-%2B-seimpersonate-copy-token> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1476 | seimpersonate-from-high-to-system | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/seimpersonate-from-high-to-system> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1477 | semanagevolume-perform-volume-maintenance-tasks | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1478 | service-triggers | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/service-triggers> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1479 | telephony-tapsrv-arbitrary-dword-write-to-rce | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/telephony-tapsrv-arbitrary-dword-write-to-rce> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1480 | uiaccess-admin-protection-bypass | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/uiaccess-admin-protection-bypass> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1481 | windows-c-payloads | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/windows-c-payloads> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1482 | windows-kernel-rootkits-and-dkom | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/windows-kernel-rootkits-and-dkom> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1483 | windows-registry-hive-exploitation | <https://book.hacktricks.wiki/en/src/windows-hardening/windows-local-privilege-escalation/windows-registry-hive-exploitation> | ~ | HackTricks-wiki/hacktricks (tree) |
| 1484 | — | <https://cloudbric.zendesk.com> | ~ | Awesome-WAF |
| 1485 | Dark Reading | <https://darkreading.com/Default.asp> | ~ | awesome-web-security |
| 1486 | Cache poisoning and other dirty tricks | <https://lab.wallarm.com/cache-poisoning-and-other-dirty-tricks-120468f1053f> | ~ | awesome-web-security |
| 1487 | Neatly bypassing CSP | <https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa> | ~ | awesome-web-security |
| 1488 | XXE that can Bypass WAF | <https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0> | ~ | Awesome-WAF |
| 1489 | CSV Injection -> Meterpreter on Pornhub | <https://news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf> | ~ | awesome-web-security |
| 1490 | Exploiting Node.js deserialization bug for Remote Code Execution | <https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution> | ~ | awesome-web-security |
| 1491 | OpSecX | <https://opsecx.com/index.php/author/ajinabraham> | ~ | awesome-web-security |
| 1492 | WebLogic RCE (CVE-2019-2725) Debug Diary | <https://paper.seebug.org/910> | ~ | awesome-web-security |
| 1493 | PENETRATION ACADEMY | <https://pentestacademy.wordpress.com> | ~ | awesome-web-security |
| 1494 | NFS \| PENETRATION TESTING ACADEMY | <https://pentestacademy.wordpress.com/2017/09/20/nfs/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=b34422ce15164e99a193fea0ccc7a02f&uid=1959680352&nid=244+289476616> | ~ | awesome-web-security |
| 1495 | @Secjuice | <https://secjuice.com> | ~ | Awesome-WAF |
| 1496 | Paul Dannewitz | <https://secjuice.com/author/paul-dannewitz> | ~ | awesome-web-security |
| 1497 | Finding The Real Origin IPs Hiding Behind CloudFlare or TOR | <https://secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor> | ~ | awesome-web-security |
| 1498 | How To Exploit PHP Remotely To Bypass Filters & WAF Rules | <https://secjuice.com/php-rce-bypass-filters-sanitization-waf> | ~ | Awesome-WAF |
| 1499 | Web Application Firewall (WAF) Evasion Techniques #3 | <https://secjuice.com/web-application-firewall-waf-evasion> | ~ | Awesome-WAF |
| 1500 | skavans | <https://skavans.ru> | ~ | awesome-web-security |
| 1501 | XXE OOB extracting via HTTP+FTP using single opened port | <https://skavans.ru/en/2017/12/02/xxe-oob-extracting-via-httpftp-using-single-opened-port> | ~ | awesome-web-security |
| 1502 | ORM2Pwn: Exploiting injections in Hibernate ORM | <https://slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm> | ~ | awesome-web-security |
| 1503 | Philippe Lin | <https://slideshare.net/miaoski> | ~ | awesome-web-security |
| 1504 | OSINT x UCCU Workshop on Open Source Intelligence | <https://slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence> | ~ | awesome-web-security |
| 1505 | ORM Injection | <https://slideshare.net/simone.onofri/orm-injection> | ~ | awesome-web-security |
| 1506 | Mario Heiderich | <https://slideshare.net/x00mario> | ~ | awesome-web-security |
| 1507 | ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and every... | <https://slideshare.net/x00mario/es6-en> | ~ | awesome-web-security |
| 1508 | JavaScript MVC and Templating Frameworks | <https://slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks> | ~ | awesome-web-security |
| 1509 | Mark Robinson | <https://sneakymonkey.net> | ~ | awesome-web-security |
| 1510 | Infosec Newbie | <https://sneakymonkey.net/2017/04/23/infosec-newbie> | ~ | awesome-web-security |
| 1511 | Databases - start.me | <https://start.me/p/QRENnO/databases> | ~ | awesome-web-security |
| 1512 | The Register | <https://theregister.co.uk> | ~ | awesome-web-security |
| 1513 | University of Michigan | <https://umich.edu> | ~ | awesome-web-security |
| 1514 | @UseNix | <https://usenix.com> | ~ | Awesome-WAF |
| 1515 | UseNix Woot'12 | <https://usenix.org/conference/woot12> | ~ | Awesome-WAF |
| 1516 | Fingerprinting Filter Rules of Web Application Firewalls - Side Channeling Attacks | <https://usenix.org/conference/woot12/workshop-program/presentation/schmitt> | ~ | Awesome-WAF |
| 1517 | voidsec | <https://voidsec.com> | ~ | awesome-web-security |
| 1518 | TL:DR: VPN leaks users’ IPs via WebRTC. I’ve tested seventy VPN providers and 16 of the... | <https://voidsec.com/vpn-leak> | ~ | awesome-web-security |
| 1519 | <img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.s... | <https://w3.org/TR/html5> | ~ | awesome-web-security |
| 1520 | Wallarm | <https://wallarm.com> | ~ | awesome-web-security |
| 1521 | Neat tricks to bypass CSRF-protection | <https://zhuanlan.zhihu.com/p/32716181> | ~ | awesome-web-security |
