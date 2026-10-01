# Interop-harness image: the RA (production dependency closure, hash-pinned)
# plus the harness-only fake-CA entrypoint and TLS/fault-injection proxy.
# The build context is the RA source tree under test; the harness files come
# from a second named context, so the harness can drive any checkout:
#   docker build -f interop/Dockerfile --build-context harness=interop <ra-tree>
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
WORKDIR /opt/ra
COPY deploy/requirements.lock.txt /opt/ra/deploy/requirements.lock.txt
RUN pip install --no-cache-dir --require-hashes -r deploy/requirements.lock.txt
COPY pyproject.toml README.md LICENSE /opt/ra/
COPY src /opt/ra/src
RUN pip install --no-cache-dir --no-deps /opt/ra
COPY --from=harness ra_harness_entry.py nonce_fault_proxy.py /opt/ra/interop/
EXPOSE 8000 443
CMD ["python", "/opt/ra/interop/ra_harness_entry.py"]
