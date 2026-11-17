"""
Secure persistent target storage and API key encryption for LLMGuard.
Protects stored credentials with AES/Fernet encryption managed server-side.
Never returns decrypted secrets to the frontend.
"""

import os
import json
import uuid
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional
from cryptography.fernet import Fernet


_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_APP_DIR)
_KEY_FILE = os.path.join(_PROJECT_DIR, ".secret.key")
_STORAGE_DIR = os.path.join(_APP_DIR, "data")
_STORAGE_FILE = os.path.join(_STORAGE_DIR, "targets.json")

_storage_lock = threading.Lock()


def _get_or_create_fernet() -> Fernet:
    """Retrieve or generate the master Fernet key for credential encryption."""
    env_key = os.getenv("LLMGUARD_SECRET_KEY")
    if env_key:
        try:
            return Fernet(env_key.strip().encode("utf-8"))
        except Exception:
            pass

    # Read from local key file
    if os.path.exists(_KEY_FILE):
        try:
            with open(_KEY_FILE, "rb") as f:
                key_bytes = f.read().strip()
                if key_bytes:
                    return Fernet(key_bytes)
        except Exception:
            pass

    # Generate new key and save to .secret.key
    new_key = Fernet.generate_key()
    try:
        with open(_KEY_FILE, "wb") as f:
            f.write(new_key)
        # Attempt to restrict permissions on POSIX
        try:
            os.chmod(_KEY_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass

    return Fernet(new_key)


_fernet = _get_or_create_fernet()


def encrypt_secret(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt a secret string into base64 ciphertext."""
    if not plaintext or not isinstance(plaintext, str):
        return None
    try:
        token = _fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")
    except Exception:
        return None


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    """Decrypt a ciphertext token back into plaintext."""
    if not ciphertext or not isinstance(ciphertext, str):
        return None
    try:
        raw = _fernet.decrypt(ciphertext.encode("utf-8"))
        return raw.decode("utf-8")
    except Exception:
        return None


def mask_api_key(key: Optional[str]) -> Optional[str]:
    """Return a masked representation of an API key (e.g. sk-...9xyz)."""
    if not key or not isinstance(key, str):
        return None
    key = key.strip()
    if len(key) <= 8:
        return "••••••••"
    prefix = key[:4]
    suffix = key[-4:]
    return f"{prefix}...{suffix}"


def _sanitize_for_client(target: Dict[str, Any]) -> Dict[str, Any]:
    """Remove ciphertext and plaintext secrets before returning to API clients."""
    clean = dict(target)
    clean.pop("encrypted_api_key", None)
    clean.pop("api_key", None)
    clean["has_api_key"] = bool(target.get("encrypted_api_key") or target.get("api_key"))
    clean["masked_api_key"] = target.get("masked_api_key")
    return clean


def _load_data() -> Dict[str, Any]:
    """Load JSON target storage."""
    os.makedirs(_STORAGE_DIR, exist_ok=True)
    if not os.path.exists(_STORAGE_FILE):
        return {"targets": []}
    try:
        with open(_STORAGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"targets": []}


def _save_data(data: Dict[str, Any]) -> None:
    """Save JSON target storage."""
    os.makedirs(_STORAGE_DIR, exist_ok=True)
    with open(_STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _init_defaults_if_empty() -> None:
    """Seed the default TechMart demo target if no targets exist."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])
        if not targets:
            default_target = {
                "id": "target-techmart-default",
                "name": "TechMart Customer Support (Demo)",
                "provider": "techmart",
                "model": "gemini-3.5-flash-lite",
                "base_url": "http://127.0.0.1:8000",
                "system_prompt": None,
                "canaries": ["TM-SECRET-938472", "TM-ADMIN-7419"],
                "allow_local_network": True,
                "authorization_confirmed": True,
                "is_active": True,
                "status": "online",
                "last_tested": datetime.now().isoformat(),
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "encrypted_api_key": None,
                "masked_api_key": None,
            }
            data["targets"] = [default_target]
            _save_data(data)


# Initialize default target on import
_init_defaults_if_empty()


def get_all_targets(include_secrets: bool = False) -> List[Dict[str, Any]]:
    """List all configured targets."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])

    result = []
    for t in targets:
        copy_t = dict(t)
        if include_secrets:
            enc = copy_t.get("encrypted_api_key")
            copy_t["api_key"] = decrypt_secret(enc) if enc else None
            result.append(copy_t)
        else:
            result.append(_sanitize_for_client(copy_t))
    return result


def get_target_by_id(target_id: str, include_secrets: bool = False) -> Optional[Dict[str, Any]]:
    """Retrieve a target by its ID."""
    with _storage_lock:
        data = _load_data()
        for t in data.get("targets", []):
            if t["id"] == target_id:
                copy_t = dict(t)
                if include_secrets:
                    enc = copy_t.get("encrypted_api_key")
                    copy_t["api_key"] = decrypt_secret(enc) if enc else None
                    return copy_t
                return _sanitize_for_client(copy_t)
    return None


def get_active_target(include_secrets: bool = False) -> Optional[Dict[str, Any]]:
    """Retrieve the currently active target (falls back to first target)."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])
        if not targets:
            return None

        for t in targets:
            if t.get("is_active"):
                copy_t = dict(t)
                if include_secrets:
                    enc = copy_t.get("encrypted_api_key")
                    copy_t["api_key"] = decrypt_secret(enc) if enc else None
                    return copy_t
                return _sanitize_for_client(copy_t)

        # Fallback to first
        copy_t = dict(targets[0])
        if include_secrets:
            enc = copy_t.get("encrypted_api_key")
            copy_t["api_key"] = decrypt_secret(enc) if enc else None
            return copy_t
        return _sanitize_for_client(copy_t)


def save_target(target_in: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new target configuration."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])

        target_id = target_in.get("id") or f"target-{uuid.uuid4().hex[:8]}"
        raw_key = target_in.get("api_key")
        encrypted_key = encrypt_secret(raw_key) if raw_key else None
        masked_key = mask_api_key(raw_key) if raw_key else None

        # Check if first target, make it active
        is_active = target_in.get("is_active", False)
        if not targets:
            is_active = True
        elif is_active:
            for t in targets:
                t["is_active"] = False

        record = {
            "id": target_id,
            "name": target_in.get("name", "New Target"),
            "provider": (target_in.get("provider") or "custom").lower(),
            "model": target_in.get("model", ""),
            "base_url": target_in.get("base_url"),
            "system_prompt": target_in.get("system_prompt"),
            "canaries": target_in.get("canaries") or [],
            "headers": target_in.get("headers"),
            "request_template": target_in.get("request_template"),
            "response_path": target_in.get("response_path"),
            "allow_local_network": bool(target_in.get("allow_local_network", False)),
            "authorization_confirmed": bool(target_in.get("authorization_confirmed", False)),
            "is_active": is_active,
            "status": "untested",
            "last_tested": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "encrypted_api_key": encrypted_key,
            "masked_api_key": masked_key,
        }

        targets.append(record)
        data["targets"] = targets
        _save_data(data)

        return _sanitize_for_client(record)


def update_target(target_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update an existing target configuration."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])
        found = None

        for t in targets:
            if t["id"] == target_id:
                found = t
                break

        if not found:
            return None

        # Update fields if provided
        for field in ("name", "provider", "model", "base_url", "system_prompt",
                      "canaries", "headers", "request_template", "response_path",
                      "status", "last_tested", "allow_local_network", "authorization_confirmed"):
            if field in updates and updates[field] is not None:
                found[field] = updates[field]

        # Handle API key: if a new key is provided (and not a masked placeholder), encrypt it
        new_key = updates.get("api_key")
        if new_key and isinstance(new_key, str) and not new_key.startswith("••"):
            found["encrypted_api_key"] = encrypt_secret(new_key)
            found["masked_api_key"] = mask_api_key(new_key)

        # Handle is_active toggle
        if updates.get("is_active"):
            for t in targets:
                t["is_active"] = (t["id"] == target_id)

        found["updated_at"] = datetime.now().isoformat()
        _save_data(data)

        return _sanitize_for_client(found)


def delete_target(target_id: str) -> bool:
    """Delete a target by ID."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])
        new_targets = [t for t in targets if t["id"] != target_id]

        if len(new_targets) == len(targets):
            return False

        # If deleted target was active, designate first remaining target active
        has_active = any(t.get("is_active") for t in new_targets)
        if not has_active and new_targets:
            new_targets[0]["is_active"] = True

        data["targets"] = new_targets
        _save_data(data)
        return True


def set_active_target(target_id: str) -> Optional[Dict[str, Any]]:
    """Set the specified target as active."""
    with _storage_lock:
        data = _load_data()
        targets = data.get("targets", [])
        found = None

        for t in targets:
            if t["id"] == target_id:
                t["is_active"] = True
                found = t
            else:
                t["is_active"] = False

        if not found:
            return None

        _save_data(data)
        return _sanitize_for_client(found)
