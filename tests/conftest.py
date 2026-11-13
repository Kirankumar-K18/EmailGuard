"""Shared pytest fixtures. Adds the project root to sys.path and isolates the database."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def tmp_db(tmp_path):
    """A fresh, initialised SQLite database file for one test."""
    from database import db

    path = tmp_path / "test.db"
    db.init_db(path)
    return path


@pytest.fixture(scope="session")
def rsa_key():
    """One RSA-2048 key for the whole session (generation takes about a second)."""
    from modules import rsa_signature

    return rsa_signature.generate_keypair(2048)


SIMPLE_EMAIL = (
    "Return-Path: <sender@example.com>\r\n"
    "Received: from mail.example.com (mail.example.com [203.0.113.7]) by mx.example.net with ESMTP id 1; Thu, 12 Nov 2026 10:00:05 +0000\r\n"
    "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=pass header.from=example.com\r\n"
    "From: Sender Name <sender@example.com>\r\n"
    "To: Receiver <receiver@example.net>\r\n"
    "Subject: Hello there\r\n"
    "Date: Thu, 12 Nov 2026 10:00:00 +0000\r\n"
    "Message-ID: <abc@example.com>\r\n"
    "\r\n"
    "Plain body with a link https://example.com/page\r\n"
)


@pytest.fixture()
def simple_email() -> str:
    return SIMPLE_EMAIL
