"""Persistent scan history storage. Optional — enabled via config."""

from asynx6.storage.db import Storage, init_db

__all__ = ["Storage", "init_db"]