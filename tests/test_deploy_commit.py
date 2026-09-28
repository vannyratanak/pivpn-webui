import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = ROOT / "deploy" / "deploy-commit.sh"


def run_git(*args, cwd, env=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True,
        capture_output=True, text=True,
    )


def deployment_repo(tmp_path):
    origin = tmp_path / "origin.git"
    run_git("init", "--bare", "-b", "main", str(origin), cwd=tmp_path)
    repo = tmp_path / "checkout"
    run_git("clone", str(origin), str(repo), cwd=tmp_path)
    run_git("config", "user.name", "deploy test", cwd=repo)
    run_git("config", "user.email", "deploy-test@example.invalid", cwd=repo)
    deploy_dir = repo / "deploy"
    deploy_dir.mkdir()
    script = deploy_dir / "deploy-commit.sh"
    shutil.copy2(DEPLOY_SCRIPT, script)
    script.chmod(0o755)
    (repo / "tracked.txt").write_text("deployed\n")
    run_git("add", ".", cwd=repo)
    run_git("commit", "-m", "deploy target", cwd=repo)
    run_git("push", "origin", "main", cwd=repo)
    sha = run_git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    return origin, repo, sha, script


def fake_sudo(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sudo = bin_dir / "sudo"
    sudo.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SUDO_LOG\"\n")
    sudo.chmod(0o755)
    return bin_dir


def run_deploy(script, repo, sha, tmp_path):
    log = tmp_path / "sudo.log"
    env = os.environ.copy()
    env["SSH_ORIGINAL_COMMAND"] = sha
    env["SUDO_LOG"] = str(log)
    env["PATH"] = f"{fake_sudo(tmp_path)}:{env['PATH']}"
    result = subprocess.run(
        [str(script), "hub"], cwd=repo, env=env,
        capture_output=True, text=True,
    )
    return result, log


def test_deploy_rejects_unvalidated_command_without_side_effects(tmp_path):
    _, repo, _, script = deployment_repo(tmp_path)
    result, log = run_deploy(script, repo, "not-a-commit", tmp_path)
    assert result.returncode == 2
    assert "40-character" in result.stderr
    assert not log.exists()


def test_deploy_requires_sha_to_be_current_origin_main(tmp_path):
    _, repo, _, script = deployment_repo(tmp_path)
    result, log = run_deploy(script, repo, "a" * 40, tmp_path)
    assert result.returncode == 1
    assert "no longer the current origin/main" in result.stderr
    assert not log.exists()


def test_deploy_restarts_only_hub_web_services_after_exact_commit(tmp_path):
    _, repo, sha, script = deployment_repo(tmp_path)
    result, log = run_deploy(script, repo, sha, tmp_path)
    assert result.returncode == 0, result.stderr
    assert f"Deployed {sha} (hub)." in result.stdout
    assert log.read_text().splitlines() == [
        "-n systemctl restart pivpn-webui-overview-stream",
        "-n systemctl restart pivpn-webui",
    ]


def test_deploy_refuses_dirty_checkout(tmp_path):
    _, repo, sha, script = deployment_repo(tmp_path)
    (repo / "tracked.txt").write_text("local edit\n")
    result, log = run_deploy(script, repo, sha, tmp_path)
    assert result.returncode == 1
    assert "local changes" in result.stderr
    assert not log.exists()
