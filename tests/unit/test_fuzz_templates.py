"""Tests for fuzz.templates."""

from __future__ import annotations

from types import SimpleNamespace

import responses

from asynx6.fuzz.templates import (
    Template, _render, _match, load_templates, run_templates,
)


GOOD_YAML = """
id: sample-status
info:
  name: Sample status check
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status: [200]
"""


def test_load_good_template(tmp_path):
    p = tmp_path / "ok.yaml"
    p.write_text(GOOD_YAML)
    t = load_templates(tmp_path)
    assert len(t) == 1
    assert t[0].id == "sample-status"
    assert t[0].severity.value == "HIGH"


def test_load_skips_bad_yaml(tmp_path):
    (tmp_path / "bad.yaml").write_text("not a valid template: [")
    assert load_templates(tmp_path) == []


def test_render():
    assert _render("{{BaseURL}}/x", "https://a.com/") == "https://a.com/x"


class TestMatcher:
    def test_status_match(self):
        r = SimpleNamespace(status_code=200, text="", headers={})
        tmpl = Template.model_validate({
            "id": "x", "info": {"name": "x", "severity": "low"},
            "requests": [{
                "method": "GET", "path": ["/"],
                "matchers": [{"type": "status", "status": [200]}],
            }],
        })
        assert _match(tmpl.requests[0].matchers[0], r)

    def test_word_match(self):
        r = SimpleNamespace(status_code=200, text="hello world",
                            headers={})
        tmpl = Template.model_validate({
            "id": "x", "info": {"name": "x", "severity": "low"},
            "requests": [{
                "method": "GET", "path": ["/"],
                "matchers": [{"type": "word", "words": ["hello"]}],
            }],
        })
        assert _match(tmpl.requests[0].matchers[0], r)

    def test_word_no_match(self):
        r = SimpleNamespace(status_code=200, text="goodbye",
                            headers={})
        tmpl = Template.model_validate({
            "id": "x", "info": {"name": "x", "severity": "low"},
            "requests": [{
                "method": "GET", "path": ["/"],
                "matchers": [{"type": "word", "words": ["missing"]}],
            }],
        })
        assert not _match(tmpl.requests[0].matchers[0], r)


@responses.activate
def test_run_templates_matches(client):
    responses.add(responses.GET, "https://x.test/probe", status=200, body="ok")
    t = Template.model_validate({
        "id": "x", "info": {"name": "x", "severity": "high"},
        "requests": [{"method": "GET", "path": ["{{BaseURL}}/probe"],
                      "matchers": [{"type": "status", "status": [200]}]}],
    })
    out = run_templates([t], "https://x.test", client=client)
    assert len(out) == 1
    assert out[0].severity.value == "HIGH"