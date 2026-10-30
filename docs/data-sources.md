# Data-source register

OGDE does not ship vulnerability records in this repository. This page is the licence and attribution register the v0.3 plan requires. Recheck every source before a release that fetches or redistributes it. The software licence of this repository is MIT and is a separate question; see [V0.3.md](V0.3.md).

Nothing in `ogde inventory` or `ogde report` contacts these services.

| Source | What OGDE would use it for | Terms to respect | Attribution when a record is shown |
| --- | --- | --- | --- |
| [OSV](https://osv.dev) | Version-specific open-source advisories. Already an explicit opt-in in `scan-osv`. | Each upstream record keeps its own terms. Do not republish a bulk mirror until those terms are listed here. Queries send package names and versions, so they stay opt-in. | Name the OSV id and the upstream source the record cites. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities. v0.2.2 accepts a local snapshot and does not vouch for where it came from. | US government public catalogue. A future fetch must use HTTPS and record the digest. | Say that the flag came from the CISA catalogue, and the date of the snapshot. |
| [EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days. Scores are published for public use. | [Usage agreement](https://www.first.org/epss/): public use, with attribution. The model and the page can change. v4 is the series the plan names; newer score files exist and must be named by the model version actually fetched. | “See EPSS at https://www.first.org/epss” or the Jacobs et al. 2021 citation on that page. |
| [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) | WordPress core, plugin and theme advisories. | Free for commercial use under Wordfence’s Intelligence terms. Read those terms again before the first fetch. Records can carry copyright notices, including MITRE’s where the record includes CVE material. | Show the notices that arrived on that record. Do not drop them. |

CycloneDX is a file format for inventories, not a feed. Advisory text from any source stays data: it is validated and escaped, and it is not executed.
