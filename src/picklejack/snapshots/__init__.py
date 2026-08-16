"""Snapshot serialization boundaries.

``secure`` parses a data-only snapshot into an explicit schema and never
reconstructs arbitrary objects. The defence-in-depth integrity-authenticated path
and the intentionally vulnerable path are added in later issues.
"""
