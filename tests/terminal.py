"""Helpers for the tests that care whether output is coloured.

Colour is decided by three things at once -- the ``--no-color`` flag, the
``NO_COLOR`` environment variable, and whether stdout is a terminal -- so a
test about any one of them has to control the other two. Both the ``scan`` and
``history`` suites need that, and they needed it identically, which is why it
lives here rather than twice.

:func:`temporary_env` restores what it found, including the case where the
variable was not set at all. That matters more than it looks: a developer with
``NO_COLOR`` exported in their own shell would otherwise see the tests that
assert colour *appears* fail on their machine and nowhere else.
"""

import contextlib
import io
import os


class TtyStringIO(io.StringIO):
    """A buffer that claims to be a terminal, because colour depends on it."""

    def isatty(self) -> bool:
        return True


@contextlib.contextmanager
def temporary_env(**values):
    """Set environment variables for the block, restoring them afterwards.

    A value of None removes the variable rather than setting it, which is how
    a test says "as if the user had never exported this".
    """
    previous = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
