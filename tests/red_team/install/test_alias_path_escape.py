"""Regression traps for the ensure_path_within defense-in-depth guards.

The install pipeline computes an ``install_path`` from a user-supplied alias
in two phases:

- ``src/apm_cli/install/phases/download.py:65``  -- before any download bytes
  land at an alias-derived destination.
- ``src/apm_cli/install/phases/integrate.py:622`` -- before the alias-derived
  path is handed to materialization / integration.

Even when the parser (``parse_alias_override``) is bypassed -- e.g. a crafted
DependencyReference carrying an alias that navigates with ``..`` or a symlink
that resolves outside ``apm_modules_dir`` -- these guards are the last line
that keeps ``install_path`` inside ``apm_modules_dir`` (the PR body "Scenario
4" claim: the install path can never escape apm_modules even if the parser is
bypassed).

These tests drive both phase entry points directly with malicious aliases and
assert the guard raises before any bytes are written / materialized.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apm_cli.install.context import InstallContext
from apm_cli.utils.path_security import PathTraversalError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_download_ctx(tmp_path: Path) -> InstallContext:
    project_root = tmp_path / "project"
    project_root.mkdir()
    apm_dir = project_root / ".apm"
    apm_dir.mkdir()
    modules = project_root / "apm_modules"
    modules.mkdir()

    ctx = InstallContext(project_root=project_root, apm_dir=apm_dir)
    ctx.apm_modules_dir = modules
    ctx.deps_to_install = []
    ctx.callback_downloaded = frozenset()
    ctx.callback_failures = set()
    ctx.existing_lockfile = None
    ctx.update_refs = False
    ctx.parallel_downloads = 4
    ctx.downloader = MagicMock()
    ctx.pre_download_results = {}
    ctx.content_hash_verified_deps = set()
    return ctx


def _make_integrate_ctx(tmp_path: Path) -> InstallContext:
    project_root = tmp_path / "project"
    project_root.mkdir()
    apm_dir = project_root / ".apm"
    apm_dir.mkdir()
    modules = project_root / "apm_modules"
    modules.mkdir()

    ctx = InstallContext(project_root=project_root, apm_dir=apm_dir)
    ctx.apm_modules_dir = modules
    ctx.deps_to_install = []
    ctx.all_apm_deps = []
    ctx.callback_failures = set()
    ctx.callback_downloaded = frozenset()
    ctx.pre_downloaded_keys = set()
    ctx.existing_lockfile = None
    ctx.diagnostics = MagicMock()
    ctx.tui = None
    ctx.root_has_local_primitives = False
    ctx.installed_count = 0
    ctx.unpinned_count = 0
    ctx.installed_packages = []
    ctx.package_deployed_files = {}
    ctx.package_types = {}
    ctx.package_hashes = {}
    ctx.total_prompts_integrated = 0
    ctx.total_agents_integrated = 0
    ctx.total_skills_integrated = 0
    ctx.total_sub_skills_promoted = 0
    ctx.total_instructions_integrated = 0
    ctx.total_commands_integrated = 0
    ctx.total_hooks_integrated = 0
    ctx.total_links_resolved = 0
    ctx.managed_files = set()
    ctx.old_local_deployed = []
    return ctx


def _make_dep_ref(key: str, *, alias: str, is_local: bool = True) -> MagicMock:
    """Build a MagicMock DependencyReference carrying a crafted *alias*.

    ``is_local`` defaults to True so the guard -- which fires BEFORE the
    local-skip branch in both phases -- is exercised without needing to
    mock the full git downloader.
    """
    dep = MagicMock()
    dep.get_unique_key.return_value = key
    dep.get_identity.return_value = key
    dep.get_display_name.return_value = key
    dep.alias = alias
    dep.is_local = is_local
    dep.local_path = "./local" if is_local else None
    return dep


# ---------------------------------------------------------------------------
# Download phase guard (download.py:65)
# ---------------------------------------------------------------------------


class TestDownloadRejectsEscapingAlias:
    def test_dotdot_alias_rejected(self, tmp_path: Path) -> None:
        from apm_cli.install.phases.download import run

        ctx = _make_download_ctx(tmp_path)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="../../etc")]

        with pytest.raises(PathTraversalError):
            run(ctx)

        ctx.downloader.download_package.assert_not_called()

    def test_symlink_escape_alias_rejected(self, tmp_path: Path) -> None:
        from apm_cli.install.phases.download import run

        ctx = _make_download_ctx(tmp_path)
        outside = tmp_path / "outside_target"
        outside.mkdir()
        link = ctx.apm_modules_dir / "evil_link"
        link.symlink_to(outside)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="evil_link")]

        with pytest.raises(PathTraversalError):
            run(ctx)

        ctx.downloader.download_package.assert_not_called()


# ---------------------------------------------------------------------------
# Integrate phase guard (integrate.py:622)
# ---------------------------------------------------------------------------


class TestIntegrateRejectsEscapingAlias:
    def test_dotdot_alias_rejected(self, tmp_path: Path) -> None:
        from apm_cli.install.phases.integrate import run

        ctx = _make_integrate_ctx(tmp_path)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="../../etc")]

        with pytest.raises(PathTraversalError):
            run(ctx)

    def test_symlink_escape_alias_rejected(self, tmp_path: Path) -> None:
        from apm_cli.install.phases.integrate import run

        ctx = _make_integrate_ctx(tmp_path)
        outside = tmp_path / "outside_target"
        outside.mkdir()
        link = ctx.apm_modules_dir / "evil_link"
        link.symlink_to(outside)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="evil_link")]

        with pytest.raises(PathTraversalError):
            run(ctx)


# ---------------------------------------------------------------------------
# Control: a safe alias must pass through both guards (no false positive)
# ---------------------------------------------------------------------------


class TestSafeAliasPasses:
    def test_safe_alias_passes_download(self, tmp_path: Path) -> None:
        from apm_cli.install.phases.download import run

        ctx = _make_download_ctx(tmp_path)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="safe-name")]

        run(ctx)

        expected = ctx.apm_modules_dir / "safe-name"
        assert expected.resolve().is_relative_to(ctx.apm_modules_dir.resolve())

    @patch("apm_cli.install.phases.integrate._integrate_root_project", return_value=None)
    @patch("apm_cli.install.phases.integrate.run_integration_template")
    @patch("apm_cli.install.phases.integrate.make_dependency_source")
    def test_safe_alias_passes_integrate(
        self, mock_source, mock_template, _mock_root, tmp_path: Path
    ) -> None:
        from apm_cli.install.phases.integrate import run

        mock_source.return_value = MagicMock()
        mock_template.return_value = {
            "installed": 1,
            "unpinned": 0,
            "prompts": 0,
            "agents": 0,
            "skills": 0,
            "sub_skills": 0,
            "instructions": 0,
            "commands": 0,
            "hooks": 0,
            "links_resolved": 0,
        }

        ctx = _make_integrate_ctx(tmp_path)
        ctx.deps_to_install = [_make_dep_ref("org/pkg", alias="safe-name")]

        run(ctx)

        assert ctx.installed_count == 1
