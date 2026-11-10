"""tools/cli_goldens.py normalise() swaps a root path only where it stands as a path."""

from __future__ import annotations


def test_a_root_inside_a_url_or_a_longer_name_is_left_alone(cli_tools):
    text = "Uploading to production: https://app.paramify.com/api/v0  /app-old /apps /app.d"
    assert cli_tools.normalise(text, {"/app"}) == text


def test_a_root_standing_as_a_path_is_replaced(cli_tools):
    text = 'ran in /app/evidence, "/app" and /app.'
    assert cli_tools.normalise(text, {"/app"}) == 'ran in <repo>/evidence, "<repo>" and <repo>.'
