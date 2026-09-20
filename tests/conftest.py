"""All local tests are offline; AWS integration tests use Moto."""

import socket

import pytest
from botocore.httpsession import URLLib3Session


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError(
            "Tests cannot access the network; use Moto or mock the external transport"
        )

    monkeypatch.setattr(socket.socket, "connect", reject)
    # Fail before botocore's connection retry loop. Moto intercepts requests
    # before this transport, so real boto3 calls to its emulators still work.
    monkeypatch.setattr(URLLib3Session, "send", reject)
