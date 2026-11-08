# The runner for scripts/conformance-oidf.sh: Python with the two packages
# that the suite's scripts/run-test-plan.py imports (scripts/requirements.txt
# at the pinned suite tag). The suite's scripts are mounted at /suite.
FROM python:3.13.18-slim-bookworm
RUN pip install --no-cache-dir httpx==0.28.1 pyparsing==3.2.3
