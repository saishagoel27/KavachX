"""Fixture repositories for the code-intelligence tests.

Each builder writes a *tiny* tree with one property worth asserting on — a resolvable call chain, a
traversal sink, an unparseable file, a minified bundle, a test suite. Small on purpose: a test that
indexes the whole seeded demo takes seconds and tells you a dozen things at once, so when it fails
you learn that "something in indexing broke". These tell you which thing.
"""
