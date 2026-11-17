"""Opt-in local staging guard/fixtures. Nothing executes merely by importing this file."""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

PROJECT = "ath-dolivy-staging"
ROOT = Path(__file__).resolve().parents[1]
TOKEN = "123456:TEST_ONLY_NOT_A_REAL_BOT"  # Public fake, identical to tests/test_web.py.
DB_PATTERN = re.compile(r"postgresql\+asyncpg://test:[0-9a-f]{32,64}@staging-postgres:5432/test")
EMPTY = (
    "BOT_TOKEN", "WEBAPP_URL", "API_ORIGIN", "HTX_API_KEY", "HTX_API_SECRET",
    "BYBIT_API_KEY", "BYBIT_API_SECRET", "HTX_DEPOSIT_ADDRESS", "BYBIT_UID",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
)
FIXED = {
    "ATH_STAGING": "isolated-v1", "MODE": "test",
    "REDIS_URL": "redis://staging-redis:6379/0",
    "TEST_REDIS_URL": "redis://staging-redis:6379/15",
    "DATA_ENCRYPTION_PREVIOUS_KEYS": "[]", "ADMIN_TELEGRAM_IDS": "[100]",
    "EXCHANGE_READS_ENABLED": "false", "RAPIRA_PUBLIC_RATES_ENABLED": "false",
    "RAPIRA_URL": "https://rapira.staging.invalid/",
    "HTX_BASE_URL": "https://htx.staging.invalid/",
    "HTX_AUTO_CREDIT_ENABLED": "true", "REAL_CREDITS_DISABLED": "true",
    "BYBIT_BASE_URL": "https://bybit.staging.invalid/",
    "HTX_ACCOUNT": "STAGING-ONLY", "RECEIPT_ARCHIVE_DIR": "/tmp/staging-evidence",
}
APP_COMMANDS = {"migrate": "migrate", "seed": "seed", "api": "api", "worker": "worker",
                "bot": "bot", "tests": "tests"}
SERVICES = {*APP_COMMANDS, "staging-postgres", "staging-redis", "frontend-tests"}
HOST_ACTIONS = ("status", "pull", "build", "up", "api", "worker", "bot", "migrate", "seed",
                "tests", "frontend-tests", "browser", "stop", "down", "destroy")
PURPOSE = "com.ath-dolivy.purpose"
SOURCE = "com.ath-dolivy.source"
PROJECT_LABEL = "com.docker.compose.project"


def local_endpoint(value):
    """Allow only known local transports; never TCP, SSH, UNC remote pipes or forwarding URLs."""
    if os.name == "nt":
        require(value in {"npipe:////./pipe/docker_engine", "npipe:////./pipe/dockerDesktopLinuxEngine"},
                "Unconfirmed/non-local Docker endpoint")
    else:
        paths = {"/var/run/docker.sock", "/run/docker.sock"}
        if hasattr(os, "getuid"):
            paths.add(f"/run/user/{os.getuid()}/docker.sock")
        require(value.startswith("unix://") and value[7:] in paths, "Unconfirmed/non-local Docker endpoint")
        path = Path(value[7:])
        require(not path.is_symlink() and path.is_socket(), "Local Docker socket not confirmed")
    return value


class SafeDocker:
    """One endpoint/environment and a fixed command vocabulary, not a general Docker shell."""

    def __init__(self, context=None, host=None):
        ambient = dict(os.environ)
        require(not (context and host), "Choose context OR host")
        env_context, env_host = ambient.get("DOCKER_CONTEXT"), ambient.get("DOCKER_HOST")
        # Reject ambiguity rather than silently overriding a possibly production selector.
        require(not ((context or env_context) and (host or env_host)), "Conflicting Docker selectors")
        require(not (context and env_context and context != env_context), "Conflicting contexts")
        require(not (host and env_host and host != env_host), "Conflicting hosts")
        self.env = {key: ambient[key] for key in ("PATH", "SystemRoot", "WINDIR", "HOME", "USERPROFILE",
                                                "TEMP", "TMP") if key in ambient}
        self.config_dir = Path(ambient.get("DOCKER_CONFIG") or Path.home() / ".docker").resolve()
        config_file = self.config_dir / "config.json"
        if config_file.exists():
            # Docker client proxies could otherwise inject credentials at container creation time.
            require(not json.loads(config_file.read_text(encoding="utf-8-sig")).get("proxies"),
                    "Docker client proxy injection must be reviewed separately")
        executable = shutil.which("docker", path=self.env.get("PATH", ""))
        require(executable is not None, "Docker CLI unavailable")
        self.base = [executable, "--config", str(self.config_dir)]
        selected_host, selected_context = host or env_host, context or env_context
        if selected_host:
            endpoint = local_endpoint(selected_host)
        else:
            require(not selected_context or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", selected_context),
                    "Invalid Docker context")
            # Local metadata only; neither context use nor any Engine command is called here.
            metadata = self._process([*self.base, "context", "inspect", *([selected_context] if selected_context else [])])
            contexts = json.loads(metadata)
            require(isinstance(contexts, list) and len(contexts) == 1, "Unknown effective context")
            endpoint = local_endpoint(contexts[0].get("Endpoints", {}).get("docker", {}).get("Host", ""))
        self.base += ["--host", endpoint]
        self.env.update(read_example_values())
        self.env.update({"DOCKER_HOST": endpoint, "ATH_STAGING_SOURCE": str(ROOT),
                         "BUILDX_BUILDER": "default", "COMPOSE_BAKE": "false"})

    def _process(self, argv, data=None, timeout=30):
        result = subprocess.run(argv, cwd=ROOT, env=self.env, input=data, capture_output=True,
                                text=True, timeout=timeout)
        require(result.returncode == 0, "Docker command failed; raw output withheld")
        return result.stdout

    def read(self, *args):
        return self._process([*self.base, *args])

    def write(self, args, apply, data=None):
        require(apply is True, "Mutating Docker action requires --apply and owner permission")
        return self._process([*self.base, *args], data, timeout=1200)

    def compose(self, args, config=None, apply=False):
        prefix = ["compose", "--project-directory", str(ROOT), "--env-file", str(ROOT / ".env.staging"),
                  "-p", PROJECT, "-f", "-" if config else str(ROOT / "compose.staging.yaml")]
        if config is None:
            require(args == ["config", "--format", "json"], "Unvalidated Compose action refused")
            return self.read(*prefix, *args)
        # Execute the validated snapshot, not a second read of mutable YAML or shell interpolation.
        return self.write([*prefix, "--profile", "*", *args], apply, json.dumps(config))


def check_configuration(client):
    """Validate only this small staging manifest, not arbitrary Compose projects."""
    config = json.loads(client.compose(["config", "--format", "json"]))
    require(set(config) <= {"name", "services", "networks", "volumes", "x-app"}, "Unexpected Compose section")
    require(config.get("name") == PROJECT and set(config.get("services", {})) == SERVICES, "Unexpected project/services")
    expected_labels = {PURPOSE: "isolated-staging", SOURCE: str(ROOT)}
    require(set(config.get("networks", {})) == {"isolated"}, "Unexpected networks")
    network = config["networks"]["isolated"]
    require(set(network) <= {"name", "driver", "internal", "labels"}
            and network.get("internal") is True and network.get("driver") == "bridge"
            and network.get("name") == PROJECT + "_isolated" and network.get("labels") == expected_labels,
            "Unsafe staging network")
    require(set(config.get("volumes", {})) == {"postgres-data", "redis-data"}, "Unexpected volumes")
    for name, volume in config["volumes"].items():
        require(set(volume) <= {"name", "driver", "labels"} and volume.get("driver", "local") == "local"
                and volume.get("name") == PROJECT + "_" + name and volume.get("labels") == expected_labels,
                "External/foreign volume refused")
    # Unknown keys (including volumes_from, cap_add, pid/ipc, sockets and lifecycle hooks) fail closed.
    service_fields = {"image", "build", "entrypoint", "command", "working_dir", "restart", "read_only",
                      "cap_drop", "security_opt", "tmpfs", "mem_limit", "cpus", "networks", "volumes",
                      "environment", "depends_on", "profiles", "healthcheck", "labels", "network_mode"}
    for name, service in config["services"].items():
        require(set(service) <= service_fields, "Unexpected/unsafe service parameter")
        require(service.get("labels") == expected_labels and service.get("restart") == "no", "Unsafe service ownership/restart")
        if name in APP_COMMANDS or name == "frontend-tests":
            build = service.get("build", {})
            target = "frontend" if name == "frontend-tests" else "checks"
            require(set(build) == {"context", "dockerfile", "target"}
                    and Path(build["context"]).resolve() == ROOT and build["dockerfile"] == "Dockerfile"
                    and build["target"] == target, "Foreign build context/options refused")
            image = "ath-dolivy-staging-frontend:cbb39e0" if target == "frontend" else "ath-dolivy-staging-checks:cbb39e0"
            require(service.get("image") == image and service.get("profiles"), "Unexpected staging image/profile")
        if name == "frontend-tests":
            require(service.get("network_mode") == "none" and not service.get("networks")
                    and not service.get("volumes") and service.get("entrypoint") == ["npm"]
                    and service.get("command") == ["test"] and service.get("environment") == {"CI": "true"}
                    and service.get("cap_drop") == ["ALL"]
                    and service.get("security_opt") == ["no-new-privileges:true"]
                    and not service.get("depends_on") and not service.get("healthcheck")
                    and not service.get("tmpfs") and service.get("working_dir") == "/build",
                    "Unsafe frontend test service")
            continue
        require(not service.get("network_mode") and set(service.get("networks", {})) == {"isolated"}, "Foreign network refused")
        mounts = service.get("volumes", [])
        require(len(mounts) == 1, "Unexpected mounts")
        mount = mounts[0]
        if name in APP_COMMANDS:
            require(set(mount) <= {"type", "source", "target", "read_only", "bind"}
                    and mount.get("type") == "bind" and mount.get("read_only") is True
                    and Path(mount.get("source", "")).resolve() == ROOT / "scripts/staging.py"
                    and mount.get("target") == "/app/scripts/staging.py"
                    and mount.get("bind") == {"create_host_path": False}, "Foreign host mount refused")
            validate_environment(service.get("environment", {}))
            extra_environment = {"DATABASE_URL", "TEST_DATABASE_URL", "DATA_ENCRYPTION_KEY", "API_HOST",
                                 "API_PORT", "BOT_WELCOME_BANNER", "PYTHONDONTWRITEBYTECODE", "PYTEST_ADDOPTS",
                                 "DOLIV_TEST_REPORT_DIR", "NO_PROXY"}
            require(set(service["environment"]) == set(FIXED) | set(EMPTY) | extra_environment,
                    "Unexpected application environment variable")
            require(set(service.get("depends_on", {})) == {"staging-postgres", "staging-redis"}
                    and all(value.get("condition") == "service_healthy"
                            for value in service["depends_on"].values()), "Unexpected dependencies")
            require(service.get("entrypoint") == ["python", "/app/scripts/staging.py"]
                    and service.get("command") == [APP_COMMANDS[name]] and service.get("read_only") is True
                    and service.get("cap_drop") == ["ALL"]
                    and service.get("security_opt") == ["no-new-privileges:true"]
                    and service.get("working_dir") == "/app"
                    and service.get("tmpfs") == ["/tmp:rw,nosuid,nodev,size=256m,mode=1777"],
                    "Guard/security bypass refused")
        else:
            require(not set(service).intersection({"build", "entrypoint", "tmpfs", "profiles", "working_dir",
                                                   "security_opt", "cap_drop", "read_only", "depends_on"}),
                    "Unexpected data-service override")
            source, destination = ("postgres-data", "/var/lib/postgresql/data") if name == "staging-postgres" else ("redis-data", "/data")
            require(set(mount) <= {"type", "source", "target", "volume"} and mount.get("type") == "volume"
                    and mount.get("source") == source and mount.get("target") == destination
                    and not mount.get("volume"), "Foreign data mount refused")
            expected_image = "postgres:17-alpine" if name == "staging-postgres" else "redis:8.10.3-alpine"
            expected_command = ["postgres", "-c", "cluster_name=" + PROJECT] if name == "staging-postgres" else ["redis-server", "--appendonly", "yes", "--appendfsync", "everysec"]
            require(service.get("image") == expected_image and service.get("command") == expected_command,
                    "Unexpected data service")
            environment = service.get("environment", {})
            if name == "staging-postgres":
                require(environment == {"POSTGRES_USER": "test", "POSTGRES_DB": "test",
                                        "POSTGRES_PASSWORD": client.env["STAGING_DB_PASSWORD"],
                                        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256"},
                        "Unexpected PostgreSQL environment")
            else:
                require(not environment, "Unexpected Redis environment")
        health = service.get("healthcheck", {})
        expected_health = {
            "staging-postgres": ["CMD-SHELL", "pg_isready -U test -d test"],
            "staging-redis": ["CMD", "redis-cli", "ping"],
            "api": ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)"],
        }.get(name)
        require(health.get("test") == expected_health and set(health) <= {"test", "interval", "timeout", "retries"},
                "Unexpected healthcheck executable")
    return config


def resource_inventory(client):
    """Engine metadata only; inspect ownership before writes, never inspect container Env."""
    inventory = {"container": [], "network": [], "volume": []}
    formats = {
        "container": '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"mounts":{{json .Mounts}},"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"pid":{{json .HostConfig.PidMode}},"ipc":{{json .HostConfig.IpcMode}},"ports":{{json .HostConfig.PortBindings}},"networks":{{json .NetworkSettings.Networks}}}',
        "network": '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"driver":{{json .Driver}},"internal":{{json .Internal}},"containers":{{json .Containers}}}',
        "volume": '{"name":{{json .Name}},"labels":{{json .Labels}},"driver":{{json .Driver}},"options":{{json .Options}}}',
    }
    for kind in inventory:
        listing = [kind, "ls", *(["-a", "--no-trunc"] if kind == "container" else ["--no-trunc"] if kind == "network" else [])]
        name_field = ".Names" if kind == "container" else ".Name"
        id_field = ".Name" if kind == "volume" else ".ID"
        rows = client.read(*listing, "--format", "{{" + id_field + "}}|{{" + name_field + "}}")
        prefix = PROJECT + ("-" if kind == "container" else "_")
        selected = {row.split("|", 1)[0] for row in rows.splitlines() if row.split("|", 1)[1].startswith(prefix)}
        selected.update(client.read(*listing, "--filter", "label=" + PROJECT_LABEL + "=" + PROJECT,
                                    "--format", "{{" + id_field + "}}").splitlines())
        for reference in sorted(selected):
            item = json.loads(client.read(kind, "inspect", reference, "--format", formats[kind]))
            labels = item.get("labels") or {}
            require(labels.get(PROJECT_LABEL) == PROJECT and labels.get(PURPOSE) == "isolated-staging"
                    and labels.get(SOURCE) == str(ROOT), "Unconfirmed resource ownership")
            if kind == "container":
                service = labels.get("com.docker.compose.service")
                require(service in SERVICES, "Unknown project container")
                name = item["name"].lstrip("/")
                oneoff = labels.get("com.docker.compose.oneoff", "").lower() == "true"
                require(bool(re.fullmatch(re.escape(f"{PROJECT}-{service}-run-") + r"[a-z0-9]+", name))
                        if oneoff else name == f"{PROJECT}-{service}-1", "Unexpected container name")
                require(not item["privileged"] and not item["cap_add"] and item["pid"] in {"", None}
                        and item["ipc"] in {"", "private", None}, "Unexpected container privilege/namespace")
                expected_network = "none" if service == "frontend-tests" else PROJECT + "_isolated"
                require(set(item["networks"]) <= {expected_network}, "Unknown container network")
                if item["ports"]:
                    require(oneoff and service == "api" and item["ports"] == {
                        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18090"}]
                    }, "Unknown/public container port")
                for mount in item["mounts"]:
                    if mount["Type"] == "volume":
                        require((service, mount.get("Name"), mount.get("Destination")) in {
                            ("staging-postgres", PROJECT + "_postgres-data", "/var/lib/postgresql/data"),
                            ("staging-redis", PROJECT + "_redis-data", "/data"),
                        },
                                "Foreign/anonymous mounted volume")
                    elif mount["Type"] == "bind":
                        script = (ROOT / "scripts/staging.py").resolve()
                        sources = {str(script), script.as_posix()}
                        if os.name == "nt" and re.match(r"^[A-Za-z]:/", script.as_posix()):
                            drive, suffix = script.as_posix()[0].lower(), script.as_posix()[2:]
                            sources.update({f"/host_mnt/{drive}{suffix}", f"/run/desktop/mnt/host/{drive}{suffix}"})
                        require(service in APP_COMMANDS and mount.get("Destination") == "/app/scripts/staging.py"
                                and mount.get("RW") is False and mount.get("Source") in sources, "Unexpected host mount")
                    else:
                        require(mount["Type"] == "tmpfs" and mount.get("Destination") == "/tmp", "Unknown mount")
            elif kind == "network":
                require(item["name"] == PROJECT + "_isolated" and item["driver"] == "bridge"
                        and item["internal"] is True and labels.get("com.docker.compose.network") == "isolated",
                        "Unknown project network")
            else:
                alias = labels.get("com.docker.compose.volume")
                require(alias in {"postgres-data", "redis-data"} and item["name"] == PROJECT + "_" + alias
                        and item["driver"] == "local" and not item["options"], "Unknown/host-backed project volume")
            inventory[kind].append(item)
    owned_ids = {item["id"] for item in inventory["container"]}
    for network in inventory["network"]:
        require(set(network["containers"] or {}) <= owned_ids, "Unknown network attachment")
    for volume in inventory["volume"]:
        references = client.read("container", "ls", "-a", "--no-trunc", "--filter", "volume=" + volume["name"], "--format", "{{.ID}}")
        require(set(references.splitlines()) <= owned_ids, "Foreign container uses staging volume")
    return inventory


def docker_action(args):
    action = args.action
    require(action == "status" or args.apply, "Owner permission and --apply required")
    require(action not in {"down", "destroy"} or args.confirm_project == PROJECT, "Explicit project confirmation required")
    client = SafeDocker(args.context, args.host)
    config = check_configuration(client)
    inventory = resource_inventory(client)
    if action == "status":
        print("Verified local staging resources: " + ", ".join(f"{k}={len(v)}" for k, v in inventory.items()))
        return
    if action in {"stop", "down", "destroy"}:
        # Immutable container/network IDs, never broad prune or a project-wide down over unknown objects.
        ids = [item["id"] for item in inventory["container"]]
        if ids:
            client.write(["container", "stop", *ids], args.apply)
            if action != "stop":
                client.write(["container", "rm", *ids], args.apply)
        if action != "stop":
            for network in inventory["network"]:
                client.write(["network", "rm", network["id"]], args.apply)
        if action == "destroy":
            remaining = resource_inventory(client)  # Recheck volume ownership and references after removal.
            require(not remaining["container"] and not remaining["network"], "Resources changed during removal")
            for volume in remaining["volume"]:
                client.write(["volume", "rm", volume["name"]], args.apply)
    else:
        commands = {
            "pull": ["pull", "staging-postgres", "staging-redis"],
            "build": ["build", "tests", "frontend-tests"],
            "up": ["up", "-d", "--no-build", "--pull", "never", "staging-postgres", "staging-redis"],
        }
        if action in {"api", "worker", "bot"}:
            command = ["up", "-d", "--no-build", "--pull", "never", action]
        elif action in {"migrate", "seed", "tests", "frontend-tests", "browser"}:
            command = ["run", "--rm", "--no-deps", "--no-build", "--pull", "never", "-T", "--interactive=false"]
            command += ["-p", "127.0.0.1:18090:8080", "api"] if action == "browser" else [action]
        else:
            command = commands[action]
        client.compose(command, config, args.apply)
    print("Verified staging Docker action completed; raw output withheld.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_key(value):
    require(bool(re.fullmatch(r"[A-Za-z0-9_-]{43}=", value)), "Fresh staging Fernet key required")
    require(len(base64.urlsafe_b64decode(value)) == 32, "Invalid staging key")


def validate_environment(env):
    for key, value in FIXED.items():
        require(env.get(key) == value, f"Unsafe staging setting: {key}")
    for key in EMPTY:
        require(env.get(key) == "", f"Forbidden staging credential/endpoint: {key}")
    require(bool(DB_PATTERN.fullmatch(env.get("DATABASE_URL", ""))), "Unsafe DATABASE_URL")
    require(env.get("TEST_DATABASE_URL") == env["DATABASE_URL"], "Unsafe TEST_DATABASE_URL")
    validate_key(env.get("DATA_ENCRYPTION_KEY", ""))


def read_example_values():
    path = ROOT / ".env.staging"
    require(path.is_file() and not path.is_symlink(), "Create a new local .env.staging from the example")
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator == "=" and key in {"STAGING_DB_PASSWORD", "STAGING_DATA_ENCRYPTION_KEY"},
                "Only two staging-specific variables are allowed; no production environment file")
        require(key not in values, "Duplicate staging variable")
        values[key] = value
    require(bool(re.fullmatch(r"[0-9a-f]{32,64}", values.get("STAGING_DB_PASSWORD", ""))),
            "New staging-only hexadecimal password required")
    validate_key(values.get("STAGING_DATA_ENCRYPTION_KEY", ""))
    return values


def restrict_network():
    """Supplemental Python checks only: not an OS firewall or a sandbox for native/child code."""
    allowed = set()
    for host, port in (("staging-postgres", 5432), ("staging-redis", 6379)):
        for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            allowed.add((info[4][0], port))

    def audit(event, args):
        if event == "socket.getaddrinfo":
            require(args[0] in {"staging-postgres", "staging-redis"}
                    or (args[0], args[1]) in allowed
                    or (args[0], args[1]) == ("0.0.0.0", 8080), "External DNS refused")
        elif event == "socket.connect":
            address = args[1]
            require(isinstance(address, tuple) and (address[0], address[1]) in allowed,
                    "External connection refused")

    sys.addaudithook(audit)


async def verify_database(settings):
    from sqlalchemy import text

    from doliv.db import database

    engine, _ = database(settings.database_url.get_secret_value())
    try:
        async with engine.connect() as connection:
            marker, db, user = (await connection.execute(text(
                "SELECT current_setting('cluster_name'),current_database(),current_user"
            ))).one()
            require((marker, db, user) == (PROJECT, "test", "test"), "Non-staging PostgreSQL refused")
    finally:
        await engine.dispose()


def fake_files_bot():
    # Reuse existing API fixture; override its constant file IDs for multiple synthetic uploads.
    sys.path.insert(0, str(ROOT / "tests"))
    from test_web import FilesBot

    class Files(FilesBot):
        def __init__(self):
            super().__init__()
            self.contents = {}

        async def send_document(self, uid, document, **kwargs):
            require(uid in {1, 2, 3, 4, 100}, "Synthetic recipient required")
            raw = getattr(document, "data", None)
            if raw is None:
                return True
            identifier = "staging-" + hashlib.sha256(raw).hexdigest()
            self.contents[identifier] = raw
            self.sent.append(uid)
            return SimpleNamespace(document=SimpleNamespace(file_id=identifier, file_unique_id=identifier))

        async def send_photo(self, uid, photo, **kwargs):
            result = await self.send_document(uid, photo, **kwargs)
            return SimpleNamespace(photo=[result.document]) if result is not True else True

        async def get_file(self, file_id):
            require(file_id in self.contents, "Unknown synthetic file")
            return SimpleNamespace(file_path=file_id, file_size=len(self.contents[file_id]))

        async def download_file(self, path, destination):
            destination.write(self.contents[path])

    return Files()


async def seed(settings):
    from sqlalchemy import select

    from doliv.db import database
    from doliv.models import LedgerTransaction
    from doliv.service import Service

    engine, factory = database(settings.database_url.get_secret_value())
    try:
        service = Service(factory, settings)
        await service.bootstrap()
        for uid, role in ((1, "CLIENT"), (2, "EMPLOYEE"), (3, "EMPLOYEE"), (4, "ASSISTANT")):
            await service.register(uid, f"staging_{uid}", f"Synthetic {role}")
            if role != "CLIENT":
                await service.set_role(100, uid, role)
        for uid in (1, 2):
            key = f"staging-seed-v1:{uid}"
            async with factory() as session:
                exists = await session.scalar(select(LedgerTransaction.id).where(LedgerTransaction.key == key))
            if not exists:
                await service.adjust(100, uid, "1000", "CREDIT", "Synthetic staging funds only", key)
        print("Synthetic users 1/2/3/4/100 prepared; no orders or external messages created.")
    finally:
        await engine.dispose()


def runtime(command):
    validate_environment(os.environ)
    restrict_network()
    from doliv.config import Settings

    settings = Settings(_env_file=None)
    asyncio.run(verify_database(settings))
    if command == "migrate":
        # In-process Alembic keeps the network audit guard installed.
        from alembic.config import Config

        from alembic import command as alembic_command
        alembic_command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    elif command == "seed":
        asyncio.run(seed(settings))
    elif command == "tests":
        import pytest
        raise SystemExit(pytest.main(["tests", "-q", "-p", "no:cacheprovider"]))
    elif command == "api":
        import uvicorn
        from pydantic import SecretStr

        from doliv.web import create_app
        settings.bot_token = SecretStr(TOKEN)
        app = create_app(settings=settings, bot=fake_files_bot())
        uvicorn.run(app, host="0.0.0.0", port=8080, access_log=False)
    else:
        # Existing empty polling fixture, never an actual Telegram HTTP session.
        from aiogram import Bot
        from recovery_fixture import NoNetworkTelegram

        import doliv.main
        os.environ["BOT_TOKEN"] = TOKEN
        doliv.main.Bot = lambda token: Bot(token, session=NoNetworkTelegram())
        asyncio.run(doliv.main.run(command))


def preview_url(actor):
    # Synthetic login for a future loopback-only browser check; no Telegram/API requests.
    data = {"auth_date": str(int(time.time())), "query_id": "staging-only",
            "user": json.dumps({"id": actor, "first_name": "Synthetic", "username": f"staging_{actor}"})}
    secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
    data["hash"] = hmac.new(secret, "\n".join(f"{k}={v}" for k, v in sorted(data.items())).encode(),
                            hashlib.sha256).hexdigest()
    launch = urlencode({"tgWebAppData": urlencode(data), "tgWebAppVersion": "8.0",
                        "tgWebAppPlatform": "tdesktop", "tgWebAppThemeParams": "{}"})
    print("SYNTHETIC LOCAL LOGIN ONLY — never use on a production URL")
    print("http://127.0.0.1:18090/#" + launch)


def main():
    class RedactedParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, "Invalid staging command/options; values withheld.\n")

    parser = RedactedParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("check", "docker", "preview-url", "migrate", "seed", "tests", "api", "bot", "worker"))
    parser.add_argument("action", nargs="?", choices=HOST_ACTIONS)
    parser.add_argument("--actor", type=int, choices=(1, 2, 3, 4, 100), default=1)
    parser.add_argument("--context")
    parser.add_argument("--host")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-project")
    args = parser.parse_args()
    try:
        if args.command == "check":
            require(args.action is None and not args.apply, "Unexpected check options")
            check_configuration(SafeDocker(args.context, args.host))
            print("Local endpoint and static staging configuration accepted; Engine not contacted.")
        elif args.command == "docker":
            require(args.action in HOST_ACTIONS, "A fixed Docker action is required")
            docker_action(args)
        elif args.command == "preview-url":
            preview_url(args.actor)
        else:
            require(args.action is None and not args.apply and not args.context and not args.host,
                    "Runtime commands are container-only entrypoints")
            runtime(args.command)
    except Exception:
        # No exception text, environment values, DSNs or signed payloads in failure output.
        print("Staging action refused or failed; no credential values printed. Review STAGING_SETUP.md.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
