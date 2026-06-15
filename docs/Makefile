.PHONY: help rq1 rq2 rq3 rq4 rq5 artifact-check rq1-rerun rq2-rerun rq3-rerun

PYTHON ?= python3

help:
	@echo "ActPlane artifact targets"
	@echo "  make rq1            Verify frozen RQ1 expressiveness summary"
	@echo "  make rq2            Verify frozen RQ2 decision-compliance summary"
	@echo "  make rq3            Verify frozen RQ3 performance summary"
	@echo "  make rq4            Verify frozen RQ4 OctoBench summary and manifests"
	@echo "  make rq5            Verify frozen RQ5 OpenAgentSafety summary and manifests"
	@echo "  make artifact-check Verify rq1 through rq5 and artifact hygiene"
	@echo "  make rq1-rerun      Re-run RQ1 from the artifact-ready branch"
	@echo "  make rq2-rerun      Re-run RQ2 through run_eval.py; the runner manages llama.cpp"
	@echo "  make rq3-rerun      Re-run RQ3 performance benchmarks"

rq1:
	$(PYTHON) artifact/verify_results.py rq1

rq2:
	$(PYTHON) artifact/verify_results.py rq2

rq3:
	$(PYTHON) artifact/verify_results.py rq3

rq4:
	$(PYTHON) artifact/verify_results.py rq4

rq5:
	$(PYTHON) artifact/verify_results.py rq5

artifact-check:
	$(PYTHON) artifact/verify_results.py all

rq1-rerun:
	@test -f rq1-expressiveness/run_study.py || (echo "RQ1 rerun scripts live on artifact-ready; see ARTIFACT.md." >&2; exit 2)
	$(PYTHON) rq1-expressiveness/run_study.py

rq2-rerun:
	@test -f eval_scripts/run_eval.py || (echo "RQ2 rerun scripts live on artifact-ready; see ARTIFACT.md." >&2; exit 2)
	$(PYTHON) eval_scripts/run_eval.py --config full

rq3-rerun:
	$(PYTHON) rq2-performance/run_perf.py --build-actplane --configs baseline,ap-1,ap-10,ap-32,ap-100 --ops open,write,connect,fork,exec --repeats 7 --cpu 2 --output-dir rq2-performance/results/rq3-micro-rerun
	$(PYTHON) rq2-performance/run_macro.py --configs baseline,ap-32,ap-100 --workloads agent-trace,linux-build --repeats 3 --timeout-s 9000 --output-dir rq2-performance/results/rq3-macro-rerun
