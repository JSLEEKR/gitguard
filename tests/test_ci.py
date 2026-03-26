"""Tests for CI/CD integration helpers."""

import os
from unittest.mock import patch

import pytest

from gitguard.ci import (
    CIEnvironment,
    detect_ci,
    exit_code_for_ci,
    generate_github_workflow,
    generate_pre_commit_config,
    github_actions_output,
    is_ci,
)


class TestDetectCI:
    def test_local(self):
        with patch.dict(os.environ, {}, clear=True):
            assert detect_ci() == CIEnvironment.LOCAL

    def test_github_actions(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            assert detect_ci() == CIEnvironment.GITHUB_ACTIONS

    def test_gitlab_ci(self):
        with patch.dict(os.environ, {"GITLAB_CI": "true"}, clear=True):
            assert detect_ci() == CIEnvironment.GITLAB_CI

    def test_jenkins(self):
        with patch.dict(os.environ, {"JENKINS_URL": "http://jenkins"}, clear=True):
            assert detect_ci() == CIEnvironment.JENKINS

    def test_circleci(self):
        with patch.dict(os.environ, {"CIRCLECI": "true"}, clear=True):
            assert detect_ci() == CIEnvironment.CIRCLECI

    def test_travis(self):
        with patch.dict(os.environ, {"TRAVIS": "true"}, clear=True):
            assert detect_ci() == CIEnvironment.TRAVIS

    def test_azure_devops(self):
        with patch.dict(os.environ, {"BUILD_BUILDID": "123"}, clear=True):
            assert detect_ci() == CIEnvironment.AZURE_DEVOPS

    def test_bitbucket(self):
        with patch.dict(os.environ, {"BITBUCKET_BUILD_NUMBER": "1"}, clear=True):
            assert detect_ci() == CIEnvironment.BITBUCKET

    def test_unknown_ci(self):
        with patch.dict(os.environ, {"CI": "true"}, clear=True):
            assert detect_ci() == CIEnvironment.UNKNOWN


class TestIsCI:
    def test_local(self):
        with patch.dict(os.environ, {}, clear=True):
            assert is_ci() is False

    def test_in_ci(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            assert is_ci() is True


class TestGitHubActionsOutput:
    def test_no_findings(self):
        output = github_actions_output(0, 0, "PASS")
        assert "findings::0" in output
        assert "warning" not in output

    def test_with_findings(self):
        output = github_actions_output(5, 35, "FAIL")
        assert "findings::5" in output
        assert "risk_score::35" in output
        assert "warning" in output


class TestGenerators:
    def test_github_workflow(self):
        wf = generate_github_workflow()
        assert "gitguard" in wf
        assert "sarif" in wf
        assert "actions/checkout" in wf

    def test_pre_commit_config(self):
        cfg = generate_pre_commit_config()
        assert "gitguard" in cfg
        assert "pre-commit" in cfg


class TestExitCode:
    def test_no_findings(self):
        assert exit_code_for_ci(False) == 0

    def test_findings_strict(self):
        assert exit_code_for_ci(True, strict=True) == 1

    def test_findings_non_strict(self):
        assert exit_code_for_ci(True, strict=False) == 0
