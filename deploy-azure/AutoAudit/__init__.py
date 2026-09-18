"""Azure Functions entry for the AutoAudit timer trigger.

This thin wrapper is what Azure Functions invokes on schedule. It delegates to
autoauditor.azure_function.main, which runs one full auto-audit cycle.

Packaging note: the deploy script copies auditor/ and autoauditor/ into this
function app folder so the import below resolves at runtime.
"""

import logging

import azure.functions as func

from autoauditor.azure_function import main as run_audit


def main(mytimer: func.TimerRequest) -> None:
    if getattr(mytimer, "past_due", False):
        logging.info("AutoAudit timer is past due; running now.")
    summary = run_audit(mytimer)
    logging.info("AutoAudit finished: %s", summary)
