# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every collected test id is short enough for Windows.

pytest writes the running test's id into the `PYTEST_CURRENT_TEST`
environment variable, and Windows refuses a variable longer than 32767
characters: the test then errors at setup on Windows alone (issue #293).
A parametrized case takes its value as its id unless given one, so a
long value needs an explicit `id`.

The session's items are what this run selected, so only a run of the
whole suite checks every id.
"""

import pytest

# far below Windows' limit
_MAX_LENGTH = 1000


def test_every_test_id_is_short(request: pytest.FixtureRequest) -> None:
    """No item of the session has an id longer than `_MAX_LENGTH`."""
    items = request.session.items
    assert items
    too_long = [item.nodeid[:100] for item in items if len(item.nodeid) > _MAX_LENGTH]
    assert too_long == []
