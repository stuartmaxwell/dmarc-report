"""Nox sessions for the supported Python versions."""

import nox


@nox.session(python=["3.11", "3.12", "3.13", "3.14", "3.15"])
def test(session: nox.Session) -> None:
    """Run the test suite."""
    session.install(".", "pytest~=9.1")
    session.run("pytest")
