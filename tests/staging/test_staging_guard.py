"""Offline guard tests. Run with --confcutdir=tests/staging, never application fixtures."""

import base64
import builtins
import copy
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
PROJECT = "ath-dolivy-staging"
PIPE = "npipe:////./pipe/docker_engine"
PASSWORD = "a" * 48  # Synthetic, never loaded from the repository or host environment.
KEY = base64.urlsafe_b64encode(b"S" * 32).decode()
CANARY = "SYNTHETIC_SECRET_MUST_NOT_BE_LOGGED"
APP_ROLES = ("migrate", "seed", "api", "worker", "bot", "tests")


@pytest.fixture(autouse=True)
def airgap(monkeypatch):
    """Any missed mock is a test failure, including swallowed connection attempts."""
    attempts = []

    def denied(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Unmocked process/network access is forbidden")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, denied)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, denied)
    for name in ("connect", "connect_ex", "sendto", "sendmsg"):
        if hasattr(socket.socket, name):
            monkeypatch.setattr(socket.socket, name, denied)
    for name in ("system", "popen", "posix_spawn", "posix_spawnp", "execv", "execve", "spawnv", "spawnve"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, denied)
    original_import = builtins.__import__

    def safe_import(name, *args, **kwargs):
        if name == "doliv" or name.startswith("doliv."):
            denied()
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", safe_import)
    assert "doliv.service" not in sys.modules, "Use --confcutdir to exclude application conftest"
    yield
    assert not attempts, "An unmocked access attempt was blocked"


def ownership(root, **extra):
    return {"com.docker.compose.project": PROJECT, "com.ath-dolivy.purpose": "isolated-staging",
            "com.ath-dolivy.source": str(root), **extra}


def rendered_compose(root):
    """Independent synthetic Compose JSON, not a call to Docker or the validator."""
    labels = {"com.ath-dolivy.purpose": "isolated-staging", "com.ath-dolivy.source": str(root)}
    database = f"postgresql+asyncpg://test:{PASSWORD}@staging-postgres:5432/test"
    environment = {
        "ATH_STAGING": "isolated-v1", "MODE": "test", "DATABASE_URL": database,
        "TEST_DATABASE_URL": database, "REDIS_URL": "redis://staging-redis:6379/0",
        "TEST_REDIS_URL": "redis://staging-redis:6379/15", "DATA_ENCRYPTION_KEY": KEY,
        "DATA_ENCRYPTION_PREVIOUS_KEYS": "[]", "BOT_TOKEN": "", "ADMIN_TELEGRAM_IDS": "[100]",
        "WEBAPP_URL": "", "API_ORIGIN": "", "API_HOST": "0.0.0.0", "API_PORT": "8080",
        "EXCHANGE_READS_ENABLED": "false", "RAPIRA_PUBLIC_RATES_ENABLED": "false",
        "RAPIRA_URL": "https://rapira.staging.invalid/", "HTX_BASE_URL": "https://htx.staging.invalid/",
        "HTX_AUTO_CREDIT_ENABLED": "true", "REAL_CREDITS_DISABLED": "true",
        "BYBIT_BASE_URL": "https://bybit.staging.invalid/", "HTX_API_KEY": "", "HTX_API_SECRET": "",
        "BYBIT_API_KEY": "", "BYBIT_API_SECRET": "", "HTX_ACCOUNT": "STAGING-ONLY",
        "HTX_DEPOSIT_ADDRESS": "", "BYBIT_UID": "", "RECEIPT_ARCHIVE_DIR": "/tmp/staging-evidence",
        "BOT_WELCOME_BANNER": "", "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "DOLIV_TEST_REPORT_DIR": "/tmp/staging-reports", "HTTP_PROXY": "", "HTTPS_PROXY": "",
        "ALL_PROXY": "", "NO_PROXY": "*",
    }
    services = {}
    for role in APP_ROLES:
        services[role] = {
            "image": "ath-dolivy-staging-checks:cbb39e0",
            "build": {"context": str(root), "dockerfile": "Dockerfile", "target": "checks"},
            "entrypoint": ["python", "/app/scripts/staging.py"], "command": [role],
            "working_dir": "/app", "restart": "no", "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": ["/tmp:rw,nosuid,nodev,size=256m,mode=1777"],
            "networks": {"isolated": None}, "labels": copy.deepcopy(labels), "profiles": [role],
            "environment": copy.deepcopy(environment),
            "volumes": [{"type": "bind", "source": str(root / "scripts/staging.py"),
                         "target": "/app/scripts/staging.py", "read_only": True,
                         "bind": {"create_host_path": False}}],
            "depends_on": {"staging-postgres": {"condition": "service_healthy", "required": True},
                           "staging-redis": {"condition": "service_healthy", "required": True}},
        }
    services["api"]["healthcheck"] = {
        "test": ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)"],
        "interval": "10s", "timeout": "4s", "retries": 5,
    }
    services["staging-postgres"] = {
        "image": "postgres:17-alpine", "command": ["postgres", "-c", "cluster_name=" + PROJECT],
        "environment": {"POSTGRES_USER": "test", "POSTGRES_DB": "test", "POSTGRES_PASSWORD": PASSWORD,
                        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
        "volumes": [{"type": "volume", "source": "postgres-data", "target": "/var/lib/postgresql/data", "volume": {}}],
        "networks": {"isolated": None}, "restart": "no", "labels": copy.deepcopy(labels),
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U test -d test"], "interval": "3s", "timeout": "3s", "retries": 30},
    }
    services["staging-redis"] = {
        "image": "redis:8.10.3-alpine", "command": ["redis-server", "--appendonly", "yes", "--appendfsync", "everysec"],
        "volumes": [{"type": "volume", "source": "redis-data", "target": "/data", "volume": {}}],
        "networks": {"isolated": None}, "restart": "no", "labels": copy.deepcopy(labels),
        "healthcheck": {"test": ["CMD", "redis-cli", "ping"], "interval": "3s", "timeout": "3s", "retries": 30},
    }
    services["frontend-tests"] = {
        "image": "ath-dolivy-staging-frontend:cbb39e0",
        "build": {"context": str(root), "dockerfile": "Dockerfile", "target": "frontend"},
        "entrypoint": ["npm"], "command": ["test"], "working_dir": "/build",
        "environment": {"CI": "true"}, "network_mode": "none", "restart": "no", "profiles": ["frontend-checks"],
        "labels": copy.deepcopy(labels), "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
    }
    return {"name": PROJECT, "services": services,
            "networks": {"isolated": {"name": PROJECT + "_isolated", "driver": "bridge", "internal": True,
                                      "labels": copy.deepcopy(labels)}},
            "volumes": {alias: {"name": PROJECT + "_" + alias, "labels": copy.deepcopy(labels)}
                        for alias in ("postgres-data", "redis-data")}}


class DockerFixture:
    """Strict, in-memory CLI/Engine substitute. Never delegates to a real process."""

    def __init__(self, root):
        self.root = root
        self.config = rendered_compose(root)
        self.context = [{"Name": "fixture-local", "Endpoints": {"docker": {"Host": PIPE}}}]
        self.calls, self.writes, self.snapshots, self.unexpected = [], [], [], []
        self.objects = {"container": {}, "network": {}, "volume": {}}
        self.refs = {}
        self.fail = None
        self.fail_at = None
        self.after_render = self.after_write = self.before_inventory = None
        self.config_reads = 0

    def populate(self):
        cid, nid = "c" * 64, "d" * 64
        self.objects["container"][cid] = {
            "id": cid, "name": f"/{PROJECT}-api-1", "labels": ownership(self.root, **{
                "com.docker.compose.service": "api", "com.docker.compose.oneoff": "False"}),
            "mounts": [{"Type": "bind", "Source": str(self.root / "scripts/staging.py"),
                        "Destination": "/app/scripts/staging.py", "RW": False}],
            "privileged": False, "cap_add": None, "pid": "", "ipc": "private", "ports": {},
            "networks": {PROJECT + "_isolated": {"NetworkID": nid}},
        }
        self.objects["network"][nid] = {
            "id": nid, "name": PROJECT + "_isolated", "driver": "bridge", "internal": True,
            "labels": ownership(self.root, **{"com.docker.compose.network": "isolated"}),
            "containers": {cid: {"Name": f"{PROJECT}-api-1"}},
        }
        for alias in ("postgres-data", "redis-data"):
            name = PROJECT + "_" + alias
            self.objects["volume"][name] = {"name": name, "driver": "local", "options": None,
                "labels": ownership(self.root, **{"com.docker.compose.volume": alias})}
            self.refs[name] = []
        return cid, nid

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), copy.deepcopy(kwargs)))
        if self.fail is not None:
            if isinstance(self.fail, BaseException):
                raise self.fail
            return SimpleNamespace(returncode=1, stdout=CANARY, stderr=CANARY)
        if "context" in argv:
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.context), stderr="")
        tail = argv[argv.index("--host") + 2:]
        kind = tail[0]
        if tuple(tail[:2]) == self.fail_at:
            return SimpleNamespace(returncode=1, stdout=CANARY, stderr=CANARY)
        output = ""
        if kind == "compose":
            if tail[-3:] == ["config", "--format", "json"]:
                self.config_reads += 1
                output = json.dumps(self.config)
                if self.after_render:
                    self.after_render()
            else:
                assert tail[tail.index("-f") + 1] == "-", "Execution must use stdin snapshot"
                assert kwargs.get("input"), "Validated snapshot missing"
                self.snapshots.append(json.loads(kwargs["input"]))
                self.writes.append(("compose", tuple(tail)))
        elif kind in self.objects:
            operation = tail[1]
            if operation == "ls":
                if self.before_inventory:
                    self.before_inventory()
                data = list(self.objects[kind].items())
                if "--filter" in tail:
                    select = tail[tail.index("--filter") + 1]
                    if select.startswith("volume="):
                        output = "\n".join(self.refs.get(select.partition("=")[2], []))
                        return SimpleNamespace(returncode=0, stdout=output, stderr="")
                    assert select.startswith("label=")
                    label, value = select[6:].split("=", 1)
                    data = [(key, obj) for key, obj in data if (obj.get("labels") or {}).get(label) == value]
                template = tail[tail.index("--format") + 1]
                output = "\n".join(key + "|" + obj["name"].lstrip("/") if "|" in template else key
                                   for key, obj in data)
            elif operation == "inspect":
                assert ".Config.Env" not in tail[-1], "Do not read container secrets"
                output = json.dumps(self.objects[kind][tail[2]])
            elif operation in {"stop", "rm"}:
                ids = tail[2:]
                assert ids and all(key in self.objects[kind] for key in ids), "Unknown mutation target"
                self.writes.append((kind, operation, tuple(ids)))
                if operation == "rm":
                    for key in ids:
                        del self.objects[kind][key]
                        if kind == "container":
                            for network in self.objects["network"].values():
                                network["containers"].pop(key, None)
                            for refs in self.refs.values():
                                if key in refs:
                                    refs.remove(key)
                if self.after_write:
                    self.after_write()
            else:
                self.unexpected.append(tail)
                raise AssertionError("Unexpected mock Docker operation")
        else:
            self.unexpected.append(tail)
            raise AssertionError("Unexpected mock Docker command")
        return SimpleNamespace(returncode=0, stdout=output, stderr="")


@pytest.fixture
def guard(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("ath_staging_guard_under_test", REPO / "scripts/staging.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "synthetic-repo"
    root.mkdir()
    (root / "scripts").mkdir()
    (root / ".env.staging").write_text(
        f"STAGING_DB_PASSWORD={PASSWORD}\nSTAGING_DATA_ENCRYPTION_KEY={KEY}\n", encoding="utf-8")
    module.ROOT = root
    module.os = SimpleNamespace(name="nt", environ={"PATH": "fixture-path", "DOCKER_CONFIG": str(tmp_path / "docker-client")}, getuid=lambda: 1000)
    monkeypatch.setattr(module.shutil, "which", lambda *a, **k: "docker-fixture-only")
    fake = DockerFixture(root)
    monkeypatch.setattr(module.subprocess, "run", fake.run)
    yield SimpleNamespace(s=module, docker=fake, env=module.os.environ, root=root, monkeypatch=monkeypatch)
    assert not fake.unexpected


def action(name="destroy", apply=True, confirmation=PROJECT, **extra):
    return SimpleNamespace(action=name, apply=apply, confirm_project=confirmation, context=None, host=None, **extra)


@pytest.mark.parametrize("endpoint", [PIPE, "npipe:////./pipe/dockerDesktopLinuxEngine"])
def test_known_windows_local_endpoint(guard, endpoint):
    assert guard.s.local_endpoint(endpoint) == endpoint
    assert not guard.docker.calls


@pytest.mark.parametrize("endpoint", ["tcp://127.0.0.1:2375", "tcp://engine.invalid:2376", "ssh://engine.invalid",
    "http://engine.invalid", "https://engine.invalid", "", "default", "npipe:////remote/pipe/docker_engine",
    "npipe:////./pipe/unreviewed", "unix:///tmp/docker.sock", "file:///var/run/docker.sock"])
def test_remote_unknown_endpoints_refused(guard, endpoint):
    with pytest.raises(ValueError):
        guard.s.local_endpoint(endpoint)
    assert not guard.docker.calls


@pytest.mark.parametrize("path", ["/var/run/docker.sock", "/run/docker.sock", "/run/user/1000/docker.sock"])
def test_unix_socket_only_with_mocked_local_confirmation(guard, path):
    guard.s.os.name = "posix"
    guard.monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    guard.monkeypatch.setattr(Path, "is_socket", lambda self: True)
    assert guard.s.local_endpoint("unix://" + path) == "unix://" + path


@pytest.mark.parametrize("symlink,socket_exists", [(True, True), (False, False)])
def test_unconfirmed_unix_socket_refused(guard, symlink, socket_exists):
    guard.s.os.name = "posix"
    guard.monkeypatch.setattr(Path, "is_symlink", lambda self: symlink)
    guard.monkeypatch.setattr(Path, "is_socket", lambda self: socket_exists)
    with pytest.raises(ValueError):
        guard.s.local_endpoint("unix:///var/run/docker.sock")


@pytest.mark.parametrize("context,host,env", [
    ("fixture-local", PIPE, {}), (None, None, {"DOCKER_CONTEXT": "fixture-local", "DOCKER_HOST": PIPE}),
    ("fixture-local", None, {"DOCKER_HOST": "ssh://engine.invalid"}),
    (None, PIPE, {"DOCKER_CONTEXT": "unreviewed"}),
    ("fixture-local", None, {"DOCKER_CONTEXT": "different"}),
    (None, PIPE, {"DOCKER_HOST": "tcp://engine.invalid:2375"}),
])
def test_conflicting_selectors_refused_before_cli(guard, context, host, env):
    guard.env.update(env)
    with pytest.raises(ValueError):
        guard.s.SafeDocker(context=context, host=host)
    assert not guard.docker.calls


@pytest.mark.parametrize("context", [[], [{}], [{"Endpoints": {}}], [{"Endpoints": {"docker": {"Host": "ssh://engine.invalid"}}}]])
def test_context_must_confirm_local_endpoint(guard, context):
    guard.docker.context = context
    with pytest.raises(ValueError):
        guard.s.SafeDocker()
    assert not guard.docker.writes


@pytest.mark.parametrize("selector", ["cli-context", "env-context", "cli-host", "env-host", "current-context"])
def test_supported_selector_sources(guard, selector):
    kwargs = {}
    if selector == "cli-context":
        kwargs["context"] = "fixture-local"
    elif selector == "env-context":
        guard.env["DOCKER_CONTEXT"] = "fixture-local"
    elif selector == "cli-host":
        kwargs["host"] = PIPE
    elif selector == "env-host":
        guard.env["DOCKER_HOST"] = PIPE
    client = guard.s.SafeDocker(**kwargs)
    assert client.base[-2:] == ["--host", PIPE]
    assert client.env["DOCKER_HOST"] == PIPE


def test_no_cli_never_installs_or_runs_anything(guard):
    guard.monkeypatch.setattr(guard.s.shutil, "which", lambda *a, **k: None)
    with pytest.raises(ValueError):
        guard.s.SafeDocker()
    assert not guard.docker.calls


def test_valid_compose_passes_read_only_check(guard):
    client = guard.s.SafeDocker()
    config = guard.s.check_configuration(client)
    assert config["name"] == PROJECT
    assert not guard.docker.writes


@pytest.mark.parametrize("role,field,value", [
    ("api", "ports", [{"target": 8080, "published": "8080", "host_ip": "0.0.0.0"}]),
    ("api", "privileged", True), ("api", "cap_add", ["SYS_ADMIN"]),
    ("api", "pid", "host"), ("api", "ipc", "host"), ("api", "volumes_from", ["foreign"]),
    ("api", "network_mode", "host"), ("api", "devices", ["/dev/unknown"]),
    ("api", "extra_hosts", ["engine.invalid:127.0.0.1"]), ("api", "post_start", [{"command": "unreviewed"}]),
    ("api", "read_only", False), ("api", "cap_drop", []),
    ("api", "security_opt", ["seccomp=unconfined"]), ("api", "entrypoint", ["sh"]),
    ("api", "command", ["unreviewed"]), ("frontend-tests", "network_mode", "host"),
])
def test_dangerous_service_options_prevent_mutation(guard, role, field, value):
    guard.docker.config["services"][role][field] = value
    with pytest.raises(ValueError):
        guard.s.docker_action(action("up"))
    assert not guard.docker.writes


@pytest.mark.parametrize("role,field,value", [
    ("api", "tmpfs", ["/app:rw"]), ("frontend-tests", "tmpfs", ["/run:rw"]),
    ("api", "working_dir", "/unreviewed"), ("frontend-tests", "working_dir", "/unreviewed"),
])
def test_unexpected_runtime_mounts_and_paths_refused(guard, role, field, value):
    guard.docker.config["services"][role][field] = value
    with pytest.raises(ValueError):
        guard.s.docker_action(action("up"))
    assert not guard.docker.writes


@pytest.mark.parametrize("mutation", ["socket", "other-host-file", "writable-script", "foreign-volume", "external-network", "external-volume", "unknown-service", "foreign-build"])
def test_foreign_configuration_refused(guard, mutation):
    config = guard.docker.config
    api = config["services"]["api"]
    if mutation == "socket":
        api["volumes"] = [{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]
    elif mutation == "other-host-file":
        api["volumes"][0]["source"] = str(guard.root / "unreviewed-file")
    elif mutation == "writable-script":
        api["volumes"][0]["read_only"] = False
    elif mutation == "foreign-volume":
        config["volumes"]["postgres-data"]["name"] = "foreign-data"
    elif mutation == "external-network":
        config["networks"]["isolated"]["external"] = True
    elif mutation == "external-volume":
        config["volumes"]["postgres-data"]["external"] = True
    elif mutation == "unknown-service":
        config["services"]["unreviewed"] = copy.deepcopy(api)
    else:
        api["build"]["context"] = str(guard.root.parent)
    with pytest.raises(ValueError):
        guard.s.docker_action(action("up"))
    assert not guard.docker.writes


@pytest.mark.parametrize("key,value", [("DATABASE_URL", "postgresql+asyncpg://user@db.invalid/live"),
    ("REDIS_URL", "redis://redis.invalid/0"), ("BOT_TOKEN", CANARY), ("HTX_API_KEY", CANARY),
    ("BYBIT_API_SECRET", CANARY), ("API_ORIGIN", "https://api.invalid"), ("MODE", "live"),
    ("EXCHANGE_READS_ENABLED", "true"), ("RAPIRA_PUBLIC_RATES_ENABLED", "true")])
def test_forbidden_endpoints_credentials_and_live_mode_refused(guard, key, value):
    guard.docker.config["services"]["api"]["environment"][key] = value
    with pytest.raises(ValueError):
        guard.s.docker_action(action("up"))
    assert not guard.docker.writes


@pytest.mark.parametrize("kind", ["container", "network", "volume"])
@pytest.mark.parametrize("label", ["com.docker.compose.project", "com.ath-dolivy.purpose", "com.ath-dolivy.source"])
@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_foreign_ownership_labels_block_all_writes(guard, kind, label, missing):
    guard.docker.populate()
    obj = next(iter(guard.docker.objects[kind].values()))
    if missing:
        obj["labels"].pop(label)
    else:
        obj["labels"][label] = "foreign-owner"
    with pytest.raises(ValueError):
        guard.s.docker_action(action())
    assert not guard.docker.writes


@pytest.mark.parametrize("mutation", ["foreign-mount", "unknown-service", "unknown-network-peer", "foreign-volume-user", "public-port", "host-namespace", "unknown-volume", "foreign-name", "host-backed-volume"])
def test_unknown_existing_resources_block_removal(guard, mutation):
    cid, nid = guard.docker.populate()
    container = guard.docker.objects["container"][cid]
    if mutation == "foreign-mount":
        container["mounts"].append({"Type": "volume", "Name": "foreign-data", "Destination": "/foreign"})
    elif mutation == "unknown-service":
        container["labels"]["com.docker.compose.service"] = "foreign"
    elif mutation == "unknown-network-peer":
        guard.docker.objects["network"][nid]["containers"]["foreign-id"] = {"Name": "foreign"}
    elif mutation == "foreign-volume-user":
        guard.docker.refs[PROJECT + "_postgres-data"] = ["foreign-id"]
    elif mutation == "public-port":
        container["ports"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
    elif mutation == "host-namespace":
        container["pid"] = "host"
    elif mutation == "unknown-volume":
        guard.docker.objects["volume"][PROJECT + "_unknown"] = {"name": PROJECT + "_unknown", "driver": "local",
            "options": None, "labels": ownership(guard.root, **{"com.docker.compose.volume": "unknown"})}
    elif mutation == "foreign-name":
        container["name"] = "/unrelated-service"
    else:
        guard.docker.objects["volume"][PROJECT + "_postgres-data"]["options"] = {"type": "none", "o": "bind", "device": "/unreviewed"}
    with pytest.raises(ValueError):
        guard.s.docker_action(action())
    assert not guard.docker.writes


@pytest.mark.parametrize("name", ["stop", "down", "destroy", "up", "build", "pull", "api"])
def test_no_apply_means_no_docker_calls(guard, name):
    with pytest.raises(ValueError):
        guard.s.docker_action(action(name, apply=False))
    assert not guard.docker.calls


@pytest.mark.parametrize("name", ["down", "destroy"])
@pytest.mark.parametrize("confirmation", [None, "", "foreign-project"])
def test_removal_requires_exact_project_confirmation(guard, name, confirmation):
    guard.docker.populate()
    with pytest.raises(ValueError):
        guard.s.docker_action(action(name, confirmation=confirmation))
    assert not guard.docker.writes


@pytest.mark.parametrize("name", ["up", "api", "down", "destroy"])
def test_all_actions_pin_one_endpoint_and_clean_environment(guard, name):
    guard.docker.populate()
    guard.env.update({"COMPOSE_FILE": "foreign.yaml", "COMPOSE_PROFILES": "foreign", "BUILDX_BUILDER": "foreign",
                      "HTTP_PROXY": "https://proxy.invalid", "DOCKER_TLS_VERIFY": "1"})
    guard.docker.after_render = lambda: guard.env.update({"DOCKER_HOST": "ssh://changed.invalid"})
    guard.s.docker_action(action(name))
    for argv, kwargs in guard.docker.calls:
        if "context" in argv:
            continue
        assert argv[argv.index("--host") + 1] == PIPE
        env = kwargs["env"]
        assert env["DOCKER_HOST"] == PIPE and env["BUILDX_BUILDER"] == "default"
        assert not {"COMPOSE_FILE", "COMPOSE_PROFILES", "HTTP_PROXY", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT"}.intersection(env)


def test_destroy_only_removes_verified_ids_and_named_volumes(guard):
    cid, nid = guard.docker.populate()
    foreign_id = "e" * 64
    guard.docker.objects["container"][foreign_id] = {"id": foreign_id, "name": "/unrelated-service",
        "labels": {"com.docker.compose.project": "unrelated"}}
    guard.docker.objects["volume"]["unrelated-data"] = {"name": "unrelated-data", "labels": {}}
    guard.s.docker_action(action())
    assert guard.docker.writes == [("container", "stop", (cid,)), ("container", "rm", (cid,)),
        ("network", "rm", (nid,)), ("volume", "rm", (PROJECT + "_postgres-data",)),
        ("volume", "rm", (PROJECT + "_redis-data",))]
    assert set(guard.docker.objects["container"]) == {foreign_id}
    assert set(guard.docker.objects["volume"]) == {"unrelated-data"}


def test_changed_volume_owner_is_rechecked_before_volume_removal(guard):
    guard.docker.populate()

    def ownership_changed():
        guard.docker.objects["volume"][PROJECT + "_postgres-data"]["labels"]["com.ath-dolivy.source"] = "foreign-source"

    guard.docker.after_write = ownership_changed
    with pytest.raises(ValueError):
        guard.s.docker_action(action())
    assert not any(write[0] == "volume" for write in guard.docker.writes)


def test_execution_uses_the_validated_json_not_changed_yaml(guard):
    expected = copy.deepcopy(guard.docker.config)

    def changed_manifest():
        guard.docker.config["services"]["api"]["privileged"] = True

    guard.docker.before_inventory = changed_manifest
    guard.s.docker_action(action("up"))
    assert guard.docker.config_reads == 1
    assert guard.docker.snapshots == [expected]
    assert all(call[0][call[0].index("-f") + 1] == "-" for call in guard.docker.calls
               if "compose" in call[0] and call[1].get("input"))


@pytest.mark.parametrize("failure", ["exit-status", "timeout", "os-error", "malformed-context"])
def test_docker_errors_do_not_log_secrets(guard, capsys, caplog, failure):
    if failure == "timeout":
        guard.docker.fail = subprocess.TimeoutExpired([CANARY], 1, output=CANARY, stderr=CANARY)
    elif failure == "os-error":
        guard.docker.fail = OSError(CANARY)
    elif failure == "malformed-context":
        guard.docker.context = [{"Endpoints": {"docker": {"Host": CANARY}}}]
    else:
        guard.docker.fail = True
    guard.monkeypatch.setattr(sys, "argv", ["staging.py", "check"])
    with pytest.raises(SystemExit) as error:
        guard.s.main()
    assert error.value.code != 0
    captured = capsys.readouterr()
    leaked = any(secret in captured.out + captured.err + caplog.text for secret in (CANARY, PASSWORD, KEY))
    assert not leaked, "Secret redaction failed"
    assert not guard.docker.writes


@pytest.mark.parametrize("argv", [["docker", "unreviewed-" + CANARY], ["docker", "up", "--unreviewed", CANARY],
                                  ["preview-url", "--actor", CANARY]])
def test_cli_parse_errors_do_not_log_secret_values(guard, capsys, caplog, argv):
    guard.monkeypatch.setattr(sys, "argv", ["staging.py", *argv])
    with pytest.raises(SystemExit):
        guard.s.main()
    captured = capsys.readouterr()
    leaked = CANARY in captured.out + captured.err + caplog.text
    assert not leaked, "CLI parser reflected secret input"
    assert not guard.docker.calls


def test_client_proxy_injection_is_refused_without_cli_calls(guard):
    folder = Path(guard.env["DOCKER_CONFIG"])
    folder.mkdir()
    (folder / "config.json").write_text(json.dumps({"proxies": {"default": {"httpsProxy": CANARY}}}))
    with pytest.raises(ValueError):
        guard.s.SafeDocker()
    assert not guard.docker.calls


def test_direct_write_without_apply_does_not_call_subprocess(guard):
    client = guard.s.SafeDocker()
    before = len(guard.docker.calls)
    with pytest.raises(ValueError):
        client.write(["container", "rm", "unreviewed"], False)
    assert len(guard.docker.calls) == before


@pytest.mark.parametrize("argv", [["docker", "destroy", "--app", "--confirm-project", PROJECT],
                                  ["docker", "destroy", "--apply", "--confirm-pro", PROJECT],
                                  ["docker", "up", "--apply", "--privileged"]])
def test_cli_does_not_accept_abbreviations_or_arbitrary_docker_flags(guard, argv):
    guard.docker.populate()
    guard.monkeypatch.setattr(sys, "argv", ["staging.py", *argv])
    with pytest.raises(SystemExit) as error:
        guard.s.main()
    assert error.value.code != 0
    assert not guard.docker.calls


@pytest.mark.parametrize("failure", [("container", "inspect"), ("network", "ls"), ("volume", "inspect")])
def test_inventory_read_failure_prevents_mutation_and_redacts_output(guard, capsys, failure):
    guard.docker.populate()
    guard.docker.fail_at = failure
    guard.monkeypatch.setattr(sys, "argv", ["staging.py", "docker", "destroy", "--apply", "--confirm-project", PROJECT])
    with pytest.raises(SystemExit):
        guard.s.main()
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err
    assert not guard.docker.writes


@pytest.mark.parametrize("content", ["DATABASE_URL=unreviewed\n", "STAGING_DB_PASSWORD=placeholder\n",
    f"STAGING_DB_PASSWORD={PASSWORD}\nSTAGING_DB_PASSWORD={PASSWORD}\nSTAGING_DATA_ENCRYPTION_KEY={KEY}\n"])
def test_unreviewed_environment_file_cannot_reach_engine_commands(guard, content):
    (guard.root / ".env.staging").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        guard.s.SafeDocker()
    assert all("context" in argv for argv, kwargs in guard.docker.calls)
    assert not guard.docker.writes


def test_check_cli_never_reads_engine_or_executes_runtime(guard):
    guard.docker.populate()
    guard.monkeypatch.setattr(sys, "argv", ["staging.py", "check"])
    guard.s.main()
    assert not guard.docker.writes
    assert all("context" in argv or "compose" in argv for argv, kwargs in guard.docker.calls)


def test_status_does_not_mutate_existing_resources(guard):
    guard.docker.populate()
    before = copy.deepcopy(guard.docker.objects)
    guard.s.docker_action(action("status", apply=False))
    assert not guard.docker.writes and guard.docker.objects == before


@pytest.mark.parametrize("key", ["HTX_AUTO_CREDIT_ENABLED", "REAL_CREDITS_DISABLED"])
def test_htx_staging_requires_enabled_policy_and_real_credit_interlock(guard, key):
    env = {**guard.s.FIXED, **dict.fromkeys(guard.s.EMPTY, "")}
    env.update({
        "DATABASE_URL": f"postgresql+asyncpg://test:{PASSWORD}@staging-postgres:5432/test",
        "TEST_DATABASE_URL": f"postgresql+asyncpg://test:{PASSWORD}@staging-postgres:5432/test",
        "DATA_ENCRYPTION_KEY": KEY,
    })
    guard.s.validate_environment(env)
    env[key] = "false"
    with pytest.raises(ValueError, match=key):
        guard.s.validate_environment(env)
