---
name: Wrong verdict
about: A rule was reported as dead and is not, or as fireable and is not
labels: wrong-verdict
---

A wrong verdict is the worst thing this tool can produce, so these come first.

**The verdict and the rule**

What it said, and what you believe is true instead. The rule id is enough; you
do not need to paste anything from your estate.

**What the report gave as the reason**

The detail line, and the evidence tier if the finding has one.

**How you know it is wrong**

A document that carries the field, a pipeline processor the tool did not read,
a config element it mapped to the wrong event. Whatever convinced you.

**The pinned commits**

SigmaHQ commit and sensor config commit, as `pinned-sources.json` records them
for your run. A verdict is only reproducible against a stated corpus.

**Versions**

detection-gate, Python, pySigma, Elasticsearch.
