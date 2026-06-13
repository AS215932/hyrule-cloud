"""Web reachability diagnostics."""

from hyrule_cloud.services.web.checks import run_web_check, run_web_tls_deep

__all__ = ["run_web_check", "run_web_tls_deep"]
