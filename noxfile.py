"""Nox file."""

import os

import nox

os.environ.update({"PDM_IGNORE_SAVED_PYTHON": "1"})


@nox.session(python=["3.10", "3.11", "3.12", "3.13", "3.14"])
def test(session: nox.Session) -> None:
    """Run the test suite."""
    session.run_always("pdm", "install", "--dev", external=True)
    session.run("pytest")
