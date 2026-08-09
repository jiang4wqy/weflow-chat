import os

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("WEFLOW_RUN_HOST_CONTRACT") != "1",
    reason="set WEFLOW_RUN_HOST_CONTRACT=1 to read fixed installed binaries",
)


def test_fixed_host_contract():
    from weflow_chat.validator.install_copy import (
        _CONTRACT,
        _FORMAL_INSTALL,
        _verify,
    )

    assert _verify(_FORMAL_INSTALL.resolve(strict=True), _CONTRACT)
