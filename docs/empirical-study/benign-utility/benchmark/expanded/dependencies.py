"""Reuse exact public dependencies with guest-local listener metadata."""
from benchmark import dependencies as shared
from benchmark.expanded.preflight import RAW

shared.ROOT=RAW/'dependencies'
shared.ROOT.mkdir(parents=True,exist_ok=True)
# Public artifact bytes are immutable and already SHA-verified; only new process
# receipts/provenance belong to this environment-specific directory.
shared.PUBLIC=shared.BASE/'dependencies/public'

def verifier_env():return shared.verifier_env()
