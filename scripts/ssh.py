#!/usr/bin/env python3
"""JSON wrapper for SSH connections backed by KeePassVault."""
from __future__ import annotations

import configparser
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import paramiko


class SshError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def fail(code: str, message: str) -> None:
    raise SshError(code, message)


def load_profile(path: str) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError) as exc:
        fail("invalid_profile", f"Não foi possível ler o perfil: {exc.__class__.__name__}")
    if not parser.has_section("ssh"):
        fail("invalid_profile", "O perfil deve conter a seção [ssh].")
    values = {key: value.strip() for key, value in parser["ssh"].items()}
    required = {"host", "username", "auth_mode", "keepass_wrapper", "keepass_config", "keepass_entry"}
    missing = sorted(required - values.keys())
    if missing:
        fail("invalid_profile", f"Chaves ausentes no perfil: {', '.join(missing)}.")
    if values["auth_mode"] not in {"password", "key"}:
        fail("invalid_profile", "auth_mode deve ser password ou key.")
    if values["auth_mode"] == "key" and not values.get("keepass_key_attachment"):
        fail("invalid_profile", "keepass_key_attachment é obrigatório para auth_mode=key.")
    values.setdefault("port", "22")
    values.setdefault("timeout_seconds", "30")
    values.setdefault("keepass_password_field", "password")
    values.setdefault("keepass_auth_mode", "windows_credential_manager")
    values.setdefault("keepass_auth_target", "")
    values.setdefault("temp_dir", tempfile.gettempdir())
    try:
        int(values["port"])
        float(values["timeout_seconds"])
    except ValueError:
        fail("invalid_profile", "port e timeout_seconds devem ser numéricos.")
    return values


def keepass_request(profile: dict[str, str], request: dict[str, Any]) -> dict[str, Any]:
    auth: dict[str, str] = {"mode": profile["keepass_auth_mode"]}
    if profile["keepass_auth_target"]:
        auth["target"] = profile["keepass_auth_target"]
    command = [profile["keepass_wrapper"], "--config", profile["keepass_config"]]
    result = subprocess.run(command, input=json.dumps({"version": 1, **request, "auth": auth}, ensure_ascii=False), text=True, capture_output=True, check=False, timeout=float(profile["timeout_seconds"]))
    if result.returncode != 0:
        fail("keepass_error", "A KeePassVault recusou a solicitação.")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("keepass_error", "A KeePassVault retornou uma resposta inválida.")
    if response.get("ok") is not True:
        fail("keepass_error", "A KeePassVault não conseguiu resolver o segredo.")
    return response.get("data", {})


def resolve_secret(profile: dict[str, str], field: str) -> str:
    data = keepass_request(profile, {"operation": "read", "entry": {"path": profile["keepass_entry"]}, "field": field})
    value = data.get("value")
    if not isinstance(value, str):
        fail("secret_missing", "O campo de autenticação não foi encontrado.")
    return value


def export_key(profile: dict[str, str], directory: str) -> str:
    target = str(Path(directory) / profile["keepass_key_attachment"])
    keepass_request(profile, {"operation": "attachment.export", "entry": {"path": profile["keepass_entry"]}, "attachment": profile["keepass_key_attachment"], "destination": target})
    if not Path(target).is_file():
        fail("key_export_failed", "A KeePassVault não criou o arquivo temporário da chave.")
    return target


def connect(profile: dict[str, str], key_path: str | None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    known_hosts = profile.get("known_hosts", "")
    if known_hosts:
        client.load_host_keys(os.path.expandvars(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs: dict[str, Any] = {"hostname": profile["host"], "port": int(profile["port"]), "username": profile["username"], "timeout": float(profile["timeout_seconds"]), "allow_agent": False, "look_for_keys": False}
    if profile["auth_mode"] == "password":
        kwargs["password"] = resolve_secret(profile, profile["keepass_password_field"])
    else:
        kwargs["key_filename"] = key_path
        if profile.get("keepass_key_passphrase_field"):
            kwargs["passphrase"] = resolve_secret(profile, profile["keepass_key_passphrase_field"])
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        fail("ssh_authentication", "O servidor SSH recusou a autenticação.")
    except (paramiko.SSHException, OSError) as exc:
        fail("ssh_connection", f"Não foi possível conectar ao servidor SSH: {exc.__class__.__name__}")
    return client


def handle(profile: dict[str, str], request: dict[str, Any]) -> dict[str, Any]:
    if request.get("version") != 1:
        fail("unsupported_version", "Somente version=1 é suportada.")
    operation = request.get("operation")
    if operation not in {"exec", "upload", "download"}:
        fail("invalid_operation", "operation deve ser exec, upload ou download.")
    if operation == "exec" and not isinstance(request.get("command"), str):
        fail("invalid_request", "command é obrigatório para exec.")
    if operation != "exec":
        for key in ("source", "destination"):
            if not isinstance(request.get(key), str) or not request[key].strip():
                fail("invalid_request", f"{key} é obrigatório.")
    temp_root = Path(profile["temp_dir"]).resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    key_path = None
    temp_directory = None
    try:
        if profile["auth_mode"] == "key":
            temp_directory = tempfile.mkdtemp(prefix="ssh-key-", dir=str(temp_root))
            key_path = export_key(profile, temp_directory)
        client = connect(profile, key_path)
        try:
            if operation == "exec":
                stdin, stdout, stderr = client.exec_command(request["command"])
                return {"stdout": stdout.read().decode("utf-8", "replace"), "stderr": stderr.read().decode("utf-8", "replace"), "exit_code": stdout.channel.recv_exit_status()}
            sftp = client.open_sftp()
            try:
                if operation == "upload":
                    source = Path(request["source"]).resolve()
                    if not source.is_file():
                        fail("file_not_found", "O arquivo local não foi encontrado.")
                    sftp.put(str(source), request["destination"])
                else:
                    destination = Path(request["destination"]).resolve()
                    if destination.exists() and request.get("overwrite") is not True:
                        fail("destination_exists", "O destino local já existe; use overwrite=true.")
                    sftp.get(request["source"], str(destination))
            finally:
                sftp.close()
        finally:
            client.close()
    finally:
        if temp_directory:
            shutil.rmtree(temp_directory, ignore_errors=True)
    return {"operation": operation, "completed": True}


def main() -> int:
    try:
        request = json.load(sys.stdin)
        result = handle(load_profile(sys.argv[1]), request)
        print(json.dumps({"version": 1, "ok": True, "data": result}, ensure_ascii=False))
        return 0
    except SshError as exc:
        print(json.dumps({"version": 1, "ok": False, "error": {"code": exc.code, "message": exc.message}}, ensure_ascii=False))
        return 1
    except Exception:
        print(json.dumps({"version": 1, "ok": False, "error": {"code": "internal_error", "message": "Falha interna no wrapper SSH."}}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: ssh.py perfil.ini", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
