"""Schema-validated language-model calls and a provider adapter.

The pipeline uses an LLM only where the paper says so (semantic prose extraction
in M1, mechanism alternatives in M2, argument/structural choices in M3). Every
model response is validated against a small JSON-schema subset; an invalid
response spends its call budget without changing pipeline state (Section 5).

Real providers are reached through an OpenAI-compatible HTTPS endpoint using the
standard library only. A deterministic mock backend is used when no key is
configured, which keeps the whole pipeline runnable offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request

PROVIDERS = ("openai", "deepseek", "glm", "openai-compatible", "mock")


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


class LLMError(RuntimeError):
    """A provider or validation failure; does not mutate pipeline state."""


# --------------------------------------------------------------------------- #
# Minimal JSON-schema validation
# --------------------------------------------------------------------------- #

def validate_schema(schema, value, path="$"):
    """Validate ``value`` against a small object-rooted JSON-schema subset.

    Supported keywords: ``type``, ``properties``, ``required``,
    ``additionalProperties``, ``items``, ``enum``, ``const`` and ``oneOf``.
    """
    if not isinstance(schema, dict):
        raise LLMError("%s: schema must be an object" % path)
    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, dict):
            raise LLMError("%s: expected object" % path)
        if "properties" in schema:
            for key, subschema in schema["properties"].items():
                if key in value:
                    validate_schema(subschema, value[key], "%s.%s" % (path, key))
        if "required" in schema:
            for key in schema["required"]:
                if key not in value:
                    raise LLMError("%s: missing required key %r" % (path, key))
        if schema.get("additionalProperties") is False:
            allowed = set(schema.get("properties", {}))
            extra = set(value) - allowed
            if extra:
                raise LLMError("%s: unexpected keys %s" % (path, sorted(extra)))
    elif schema_type == "array":
        if not isinstance(value, list):
            raise LLMError("%s: expected array" % path)
        if "items" in schema:
            for i, item in enumerate(value):
                validate_schema(schema["items"], item, "%s[%d]" % (path, i))
    elif schema_type == "string":
        if not isinstance(value, str):
            raise LLMError("%s: expected string" % path)
    elif schema_type == "integer":
        if type(value) is not int:
            raise LLMError("%s: expected integer" % path)
    elif schema_type == "number":
        if type(value) not in (int, float) or not isinstance(value, (int, float)):
            raise LLMError("%s: expected number" % path)
    elif schema_type == "boolean":
        if type(value) is not bool:
            raise LLMError("%s: expected boolean" % path)
    else:
        # Object-rooted schemas must declare a type.
        raise LLMError("%s: unsupported schema type %r" % (path, schema_type))
    if "enum" in schema and value not in schema["enum"]:
        raise LLMError("%s: value not in enum" % path)
    if "const" in schema and value != schema["const"]:
        raise LLMError("%s: value does not match const" % path)
    if "oneOf" in schema:
        if not any(_matches(branch, value) for branch in schema["oneOf"]):
            raise LLMError("%s: value matches no oneOf branch" % path)
    return value


def _matches(schema, value):
    try:
        validate_schema(schema, value, "$")
        return True
    except LLMError:
        return False


# --------------------------------------------------------------------------- #
# Mock backend
# --------------------------------------------------------------------------- #

class MockLLM:
    """Deterministic offline backend for pipeline dry-runs and unit tests.

    It is selected automatically when no provider key is configured, and never
    pretends to be a measured model result.
    """

    def __init__(self, model="mock"):
        self.model = model
        self.calls = 0
        self.failed_calls = 0
        self.records = []

    def complete(self, messages, schema):
        self.calls += 1
        prompt = "\n".join(str(m.get("content", "")) for m in messages if isinstance(m, dict))
        record = {"model": self.model, "prompt_sha256": _hash(messages),
                  "schema_sha256": _hash(schema)}
        try:
            data = validate_schema(schema, _mock_for_prompt(prompt))
        except LLMError:
            self.failed_calls += 1
            record["ok"] = False
            self.records.append(record)
            raise
        record["ok"] = True
        self.records.append(record)
        return data


def _mock_for_prompt(prompt):
    lowered = prompt.lower()
    if "propose ranked root-cause" in lowered:
        return {
            "hypotheses": [
                {
                    "rank": 0,
                    "mechanism": "locking scope permits two deletion paths sharing the "
                                 "logical partition object to release and access the same "
                                 "holder_dir kobject allocation epoch",
                    "objects": ["O_P=hd_struct", "O_K=holder_dir kobject"],
                    "invariant": "O_K is not accessed after release within the same allocation epoch",
                    "confidence": 0.6,
                }
            ]
        }
    if "extract only semantic claims" in lowered:
        if "race" in lowered or "releases" in lowered or "deletion" in lowered:
            return {"claims": [{
                "key": "reported_mechanism",
                "value": "competing deletion paths race on the shared partition object",
                "confidence": 0.7,
            }]}
        return {"claims": []}
    if "argument" in lowered or "parameter" in lowered or "domain" in lowered:
        return {"choices": [{"value": 0, "reason": "initial finite-domain point"}]}
    # Default: return no invented values.
    return {"claims": []}


# --------------------------------------------------------------------------- #
# Provider adapter
# --------------------------------------------------------------------------- #

def _load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise LLMError("LLM config must be an object")
    return cfg


def _post_json(url, payload, api_key):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise LLMError("provider HTTP %d" % exc.code) from None
    except urllib.error.URLError as exc:
        raise LLMError("provider unreachable: %s" % exc.reason) from None
    except (ValueError, OSError) as exc:
        raise LLMError("provider response error") from exc


class LLMClient:
    """OpenAI-compatible chat completions client over the standard library.

    Every call is recorded with the model revision, prompt/schema hashes and
    outcome (Section 5 backend adapter); an invalid response spends its call
    budget without changing pipeline state.
    """

    def __init__(self, provider, base_url, api_key_env, model, api_key=None):
        if provider not in PROVIDERS:
            raise LLMError("unknown provider %r" % (provider,))
        if provider == "mock":
            self._mock = MockLLM(model)
        else:
            self._mock = None
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self.model = model
        self.api_key = api_key if api_key is not None else os.environ.get(api_key_env, "")
        self.calls = 0
        self.failed_calls = 0
        self.records = []

    @classmethod
    def from_config(cls, path):
        cfg = _load_config(path)
        if cfg.get("provider") == "mock":
            return cls("mock", "", "", "", cfg.get("model", "mock"))
        return cls(cfg["provider"], cfg["base_url"], cfg["api_key_env"], cfg["model"])

    def complete(self, messages, schema):
        """Return a schema-validated object for a list of chat messages."""
        if self._mock is not None:
            return self._mock.complete(messages, schema)
        self.calls += 1
        record = {"model": self.model, "prompt_sha256": _hash(messages),
                  "schema_sha256": _hash(schema)}
        payload = {
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        try:
            url = self.base_url + "/chat/completions"
            response = _post_json(url, payload, self.api_key)
            content = response["choices"][0]["message"]["content"]
            data = json.loads(content)
            data = validate_schema(schema, data)
        except LLMError:
            self.failed_calls += 1
            record["ok"] = False
            self.records.append(record)
            raise
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            self.failed_calls += 1
            record["ok"] = False
            self.records.append(record)
            raise LLMError("provider response malformed") from exc
        record["ok"] = True
        self.records.append(record)
        return data
