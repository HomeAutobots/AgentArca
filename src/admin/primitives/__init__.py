"""
primitives/ - Thin wrappers over host-side operator primitives.

allowlist.py wraps allowlist-local.sh via subprocess.
logs.py provides read-only readers for audit, egress, and health data.

These modules are the ONLY code that touches allowlist state or reads logs.
Route handlers call primitives; they do not call docker or open config files directly.
"""
