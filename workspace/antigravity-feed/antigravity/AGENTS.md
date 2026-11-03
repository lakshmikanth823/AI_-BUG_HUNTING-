# Workspace: Security Research Link Corpus

This workspace is a **reference corpus**, not an application. It contains
**9,879 curated, de-duplicated, HTTP-verified security-research URLs** intended to be
fed to an agent as grounding material for bug bounty and CTF work.

## What is here

| Path | Contents |
|---|---|
| `STRATEGY.md` | The methodology: how to hunt, what pays, how to pick targets |
| `TOP_PROGRAMS.md` | Data-driven enterprise program targeting guide |
| `BOOKS.md` | Curated reading list and learning path |
| `LABS.md` | Three-tier home-lab build plan |
| `INDEX.md` | Human-readable index of all 17 categories |
| `data/` | Machine-readable corpus: `.txt`, `.csv`, `.json` |
| `by-category/` | Full categorized listings with titles and verification status |
| `.agents/rules/` | This corpus, chunked into Antigravity `model_decision` rules |
| `work/` | The harvesting / validation pipeline (reproducible) |

## Agent behaviour in this workspace

- Load `.agents/rules/00-corpus-index.md` first; it is `always_on` and maps every category.
- Pull in only the category rule that matches the task. Do not read all of them.
- Prefer `grep`/`rg` over `data/` files for lookup; the corpus is too large to load wholesale.
- Treat every URL as a *lead to verify*, not a fact. Verification status is recorded per link.
- Follow the hard safety rules in the index rule file without exception.

## Regenerating / refreshing

```
cd work
python3 harvest.py && python3 harvest2.py && python3 curated.py   # collect
python3 build.py                                                  # dedupe + classify
python3 validate.py                                               # HTTP verify (~2 min)
python3 programs.py                                               # bounty program ranking
python3 emit.py && python3 mkantigravity.py                       # emit deliverables
```
