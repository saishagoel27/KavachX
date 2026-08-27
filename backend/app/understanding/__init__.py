"""The UNDERSTAND stage: what this application *is*, and what its attack surface looks like.

Indexing answers "what code exists and how is it connected". Understanding answers the questions
a security reviewer asks before looking at any single function: what kind of application is this,
what does it expose, what guards it, what does it trust, and what is untested.

* :mod:`app.understanding.tests_discovery` — multi-framework test detection and test→symbol map.
* :mod:`app.understanding.config_discovery` — configuration inventory and security-relevant settings.
* :mod:`app.understanding.dependencies` — dependency model (understanding, not advisories).
* :mod:`app.understanding.architecture` — the structured ApplicationModel.
* :mod:`app.understanding.attack_surface` — externally reachable entrypoints ranked by exposure.

All three discovery modules are called from the indexing service, so their results are part of the
index rather than a separate pass that can drift out of sync with it.
"""
