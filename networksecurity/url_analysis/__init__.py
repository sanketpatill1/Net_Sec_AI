"""URL-only security analysis utilities.

These modules never request or open a submitted URL. They derive features from
the URL string only, which keeps the public analysis endpoint SSRF-safe.
"""
