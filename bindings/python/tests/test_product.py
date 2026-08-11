from __future__ import annotations

import copy
import pickle

import pytest

from auths import AuthsConfiguration, ExecutionReference
from auths.profiles import mcp


def test_product_waist_uses_sealed_configuration_authority_and_reference() -> None:
    authority = mcp.allow_tools(["publish_report"])
    action = mcp.call_tool(name="publish_report", arguments={"week": 32})
    assert authority.tools == ("publish_report",)
    assert action.name == "publish_report"
    with pytest.raises(TypeError, match="sealed"):
        AuthsConfiguration(object(), "development", (), lambda: None)
    with pytest.raises(TypeError, match="sealed"):
        ExecutionReference(object(), "mcp1.forged")
    with pytest.raises(TypeError, match="copyable"):
        copy.copy(authority)
    with pytest.raises(TypeError, match="serializable"):
        pickle.dumps(authority)
