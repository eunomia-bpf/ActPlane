# Superseded initial complete matrix

These CSVs preserve the first complete matrix before dependency repair. The
control could not start pytest for two policies because the official pytest
dependency was absent. These pairs were excluded, never counted as prevented.
The final report uses the rerun after installing the official dependency in
both the Workspace and Docker image. Raw initial logs remain remotely under
`raw/main/`, with large closed audit files losslessly compressed.

Produced by `SANDBOX_RUN_TAG=main python3 analyze.py` before the final rerun.
The scripts in the parent folder reproduce the current final protocol; they
are not a promise to reinstall the superseded missing-dependency environment.
