# Research and implementation choices

Reviewed 26 September 2026 for UK use. These are sources of ideas;
their advertised broker counts are not evidence of successful searches or removals.
No upstream broker dataset or third-party application code was imported.

These observations are dated research, not a claim that an upstream project or
provider has retained the same behavior or access terms.

| Project | Useful ideas | Limits / licence |
| --- | --- | --- |
| [PrivacyScrub](https://github.com/bmcgarybot/privacyscrub) | Closest self-hosted dashboard found: broker inventory, request tracking, reappearance checks | MIT. Small project; its 800+ inventory claim does not establish UK adapter coverage or removal effectiveness. |
| [data_takedown](https://github.com/Jollyhrothgar/data_takedown) | Identity storage, email request queue, response classification and later verification | Early CLI project. Its optional hosted-model automation is not used here. Confirm licensing before copying. |
| [Optout](https://github.com/DrCaiola/optout) | Browser-local progress tracking and letter drafting | CC BY-NC-SA; reference only, not unrestricted software reuse. |
| [Yael Grauer's opt-out list](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List) | Human-maintained removal instructions and reminders | CC BY-NC-SA 4.0; primarily US oriented. Linked, not copied. |
| [PersProtect dataset](https://github.com/Persprotect/data-broker-opt-out-list) | Structured broker records and opt-out URLs | CC BY 4.0; US inventory, attribution required if reused. |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Modular source adapters, correlated findings and evidence provenance | MIT. Broad OSINT, not a removal service; provider keys and identity false positives need attention. |
| [AIL Framework](https://github.com/ail-project/ail-framework) | Leak collection and investigation across clear web, Tor and I2P | AGPL-3.0, heavier operational footprint. Not installed; Privacy Bot uses provider metadata instead of retrieving hostile source material. |

## Third-party exposure providers

**Selected: Have I Been Pwned.** Its documented HTTPS APIs return breach metadata
and, for eligible subscriptions and verified domains, stealer-log website domains.
No password or raw leak is fetched. Queries disclose the email to the provider;
coverage excludes some records and cannot prove universal absence. Its
[privacy policy](https://haveibeenpwned.com/Privacy) describes how it handles searches.
Check current eligibility in the [API documentation](https://haveibeenpwned.com/API/v3)
and [subscription page](https://haveibeenpwned.com/Subscription) before paying.
An ordinary consumer mailbox can be checked for breaches, but its domain cannot
usually be verified by the mailbox owner for the stealer API.

[SpyCloud Consumer Protection](https://spycloud.com/platform/consumer-protection/)
is an alternative to investigate for wider consumer exposure coverage. It is a
commercial integration aimed at organisations; no self-service personal API
entitlement, quote or connector has been verified here. No subscription purchased.

DeHashed was considered, but its documentation/privacy pages were unavailable to
the research tool. No connector or reliability claim is made without that review.

The product has no Tor client, onion adapter, raw leak downloader or dark-web
browser. A provider result is an observation in that provider's collection, not
proof that the entire dark web was searched. Raw passwords are never requested.

## UK credit reports

The [ICO identifies Experian, Equifax and TransUnion](https://ico.org.uk/for-the-public/credit/)
as the three main consumer credit reference agencies. Source connections are
separate because their files and update times differ. Access points:
[Experian](https://www.experian.co.uk/consumer/statutory-report.html),
[Equifax](https://www.equifax.co.uk/products/credit/statutory-report), and
[TransUnion](https://www.transunion.co.uk/consumer/consumer-credit).

No public consumer API entitlement was established. Owner login and representative
reports are needed to validate each real portal's extraction. Browser sessions are
available; unattended extraction is enabled only when a reviewed structured adapter
exists. PDF/text uploads expose extracted text for review; unrecognised documents
never become an empty clean report. Canonical JSON import and comparison work now.

Experian, ClearScore and Credit Karma are the default browser login routes.
ClearScore identifies its UK bureau as
[Equifax](https://help.clearscore.com/hc/en-us/articles/115005326929-About-ClearScore),
and Credit Karma identifies its UK report as
[TransUnion](https://www.creditkarma.co.uk/insights/i/identity-fraud-check-credit-report-uk).

The first complete report establishes a baseline. Later reports raise important
events for hard/unknown enquiries, new credit, address changes, defaults, public
records and relevant account changes. Soft enquiries remain recorded without
default notifications. Missing sections, malformed records and conflicting report
dates cannot overwrite the baseline. Stable IDs, not row positions, identify records.

## Removal claims and verification

Drafts use only name, contact email and the relevant listing link. The owner reviews
the target and identity match; requests are sent through configured TLS SMTP or
submitted in the source's browser. Submission, acknowledgement and verified removal
are separate states. Transport uncertainty never triggers an automatic resend.
Confirmed removal needs a recorded observation; a later match reopens attention.

The [ICO's erasure guidance](https://ico.org.uk/for-the-public/your-right-to-get-your-data-deleted/)
explains the right and its exceptions. The product does not promise deletion of
lawfully retained credit records, public records or copies already leaked elsewhere.
