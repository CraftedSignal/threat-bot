# 0003: Use synthetic deterministic evaluation fixtures

Status: accepted, 2026-11-14.

Full third-party report excerpts expanded the repository's redistribution and sensitive-data surface. The default corpus is now twelve original fictional sentences across four documents. Original dataset hashes, upstream attribution, complete-replacement details, and new hashes are retained.

Manually authored replay responses make extractor and scoring regressions deterministic. A missing fixture is a failure, not a skipped quality gate. These results say nothing about live-model accuracy. Researchers may explicitly supply an external dataset after reviewing its content and rights; default tests never download it.
