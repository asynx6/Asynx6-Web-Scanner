"""Fuzz modules: directory, api, templates (nuclei-style)."""

from asynx6.fuzz.directory import run as directory_run
from asynx6.fuzz.api import run as api_run
from asynx6.fuzz.templates import load_templates, run_templates

__all__ = ["directory_run", "api_run", "load_templates", "run_templates"]
