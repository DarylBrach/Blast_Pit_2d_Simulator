import json
from pathlib import Path


SCHEMAS = (
    "codex_build_result_v2.schema.json",
    "specialist_review_v2.schema.json",
    "final_qa_v2.schema.json",
    "improvement_operator_decision_v2.schema.json",
)


def load(name):
    return json.loads((Path(__file__).parent / "schemas" / name).read_text(encoding="utf-8"))


def walk_objects(value):
    if isinstance(value, dict):
        if value.get("type") == "object" or "properties" in value:
            yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def test_v2_schemas_are_strict_draft_2020_12_documents():
    for name in SCHEMAS:
        schema = load(name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["required"]
        assert all(node.get("additionalProperties") is False for node in walk_objects(schema))


def test_v2_schema_arrays_and_free_text_are_bounded():
    for name in SCHEMAS:
        text = json.dumps(load(name), sort_keys=True)
        assert '"type": "array"' not in text or '"maxItems"' in text
        for node in walk_nodes(load(name)):
            node_type = node.get("type")
            if node_type == "array":
                assert "maxItems" in node
            if node_type == "string" and "const" not in node and "enum" not in node and "pattern" not in node:
                assert "maxLength" in node


def walk_nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_nodes(child)


def test_specialist_roles_and_findings_are_governed():
    schema = load("specialist_review_v2.schema.json")
    assert set(schema["properties"]["role"]["enum"]) == {
        "architecture_state", "algorithm_objective", "workflow_state", "governance_evidence",
        "security_sandbox", "testing_reliability", "docs_ux",
    }
    finding = schema["$defs"]["finding"]
    assert set(finding["required"]) == {"id", "severity", "category", "file", "line", "evidence", "impact", "remediation", "test"}


def test_build_schema_carries_one_bounded_controller_applied_patch():
    schema = load("codex_build_result_v2.schema.json")
    assert "patch" in schema["required"]
    assert schema["properties"]["patch"] == {"type": "string", "maxLength": 120000}


def test_operator_decision_separates_authority_and_not_run_states():
    schema = load("improvement_operator_decision_v2.schema.json")
    properties = schema["properties"]
    assert properties["promotion_authorized"] == {"const": False}
    assert properties["release_authorized"] == {"const": False}
    assert "NOT_RUN" in properties["execution"]["enum"]
    assert "NOT_RUN" in properties["review"]["enum"]
    assert "NOT_RUN" in properties["promotion"]["enum"]
    assert "NOT_RUN" in schema["$defs"]["gate"]["properties"]["status"]["enum"]
    assert "{40}" in schema["$defs"]["git_commit"]["pattern"]


def test_jsonschema_can_compile_v2_schemas_when_available():
    try:
        import jsonschema
    except ImportError:
        return
    for name in SCHEMAS:
        jsonschema.Draft202012Validator.check_schema(load(name))


def test_codex_output_schemas_use_supported_strict_response_shape():
    for name in SCHEMAS[:3]:
        schema = load(name)
        assert all("uniqueItems" not in node for node in walk_nodes(schema))
        for node in walk_nodes(schema):
            if "const" in node or "enum" in node:
                assert "type" in node
