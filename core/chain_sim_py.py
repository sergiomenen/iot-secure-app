# core/chain_sim_py.py
# Implementación pura en Python de un ledger (append-only), control de acceso simple y actuador.
# Todo en memoria, sin dependencias externas; usa hashlib y time.

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import time
import json
import csv
import os


def _now_ts() -> float:
    return time.time()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Entry:
    id: str
    submitter: str
    timestamp: float
    data_hex: str
    pointer: Optional[str]


@dataclass
class Event:
    id: str
    timestamp: float
    kind: str
    metadata: Dict[str, Any]


class Ledger:
    """
    Ledger append-only en memoria.
    - entries: dict id -> Entry
    - events: list[Event] (ordenados por tiempo)
    Methods:
      register(submitter, data_bytes, pointer) -> entry_id
      get_entry(id) -> Entry | None
      all_entries() -> List[Entry]
      get_events(kind=None) -> List[Event]
      export_json(path) -> writes JSON with entries and events
      export_csv(entries_path, events_path) -> writes two CSVs
    """
    def __init__(self):
        self._entries: Dict[str, Entry] = {}
        self._events: List[Event] = []

    def register(self, submitter: str, data_bytes: bytes, pointer: Optional[str] = None) -> str:
        """
        Registra una entrada append-only.
        entry_id se genera como SHA-256 sobre submitter|timestamp|data|pointer.
        Devuelve entry_id.
        """
        ts = _now_ts()
        # prepare id material deterministically
        material = b"".join([
            submitter.encode("utf-8"),
            b"|",
            str(ts).encode("utf-8"),
            b"|",
            data_bytes,
            b"|",
            (pointer or "").encode("utf-8"),
        ])
        entry_id = _sha256_hex(material)
        entry = Entry(
            id=entry_id,
            submitter=submitter,
            timestamp=ts,
            data_hex=data_bytes.hex(),
            pointer=pointer,
        )
        # append-only: do not allow overwrite
        if entry_id in self._entries:
            # extremely unlikely, return existing id
            return entry_id
        self._entries[entry_id] = entry
        # also emit an event "Registered"
        ev = Event(
            id=_sha256_hex(b"event|" + entry_id.encode("utf-8") + b"|" + str(ts).encode("utf-8")),
            timestamp=ts,
            kind="Registered",
            metadata={"entry_id": entry_id, "submitter": submitter, "pointer": pointer},
        )
        self._events.append(ev)
        return entry_id

    def get_entry(self, entry_id: str) -> Optional[Entry]:
        return self._entries.get(entry_id)

    def all_entries(self) -> List[Entry]:
        # return entries ordered by timestamp ascending
        return sorted(self._entries.values(), key=lambda e: e.timestamp)

    def get_events(self, kind: Optional[str] = None) -> List[Event]:
        if kind is None:
            return list(self._events)
        return [e for e in self._events if e.kind == kind]

    def emit_event(self, kind: str, metadata: Dict[str, Any]) -> Event:
        ts = _now_ts()
        ev_id = _sha256_hex(f"{kind}|{json.dumps(metadata, sort_keys=True)}|{ts}".encode("utf-8"))
        ev = Event(id=ev_id, timestamp=ts, kind=kind, metadata=metadata)
        self._events.append(ev)
        return ev

    def export_json(self, path: str) -> None:
        """
        Exporta todo el ledger (entries y events) a un JSON en 'path'.
        """
        data = {
            "entries": [asdict(e) for e in self.all_entries()],
            "events": [asdict(ev) for ev in self._events],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def export_csv(self, entries_path: str, events_path: str) -> None:
        """
        Exporta entries y events a dos archivos CSV.
        """
        # Entries CSV
        with open(entries_path, "w", newline="", encoding="utf-8") as ef:
            writer = csv.writer(ef)
            writer.writerow(["id", "submitter", "timestamp", "data_hex", "pointer"])
            for e in self.all_entries():
                writer.writerow([e.id, e.submitter, e.timestamp, e.data_hex, e.pointer or ""])
        # Events CSV
        with open(events_path, "w", newline="", encoding="utf-8") as evf:
            writer = csv.writer(evf)
            writer.writerow(["id", "timestamp", "kind", "metadata_json"])
            for ev in self._events:
                writer.writerow([ev.id, ev.timestamp, ev.kind, json.dumps(ev.metadata, ensure_ascii=False)])


class AccessControlPy:
    """
    Control de acceso simple:
    - admins: set of principals that pueden otorgar/revocar.
    - grants: mapping (resource -> list of (principal, expiry_ts))
    Métodos:
      grant(resource, to, valid_seconds, caller)
      revoke(resource, to, caller)
      has_access(resource, who) -> bool
    """
    def __init__(self, initial_admins: Optional[List[str]] = None):
        self.admins = set(initial_admins or [])
        # grants: resource -> dict principal -> expiry_ts
        self.grants: Dict[str, Dict[str, float]] = {}

    def _now(self) -> float:
        return _now_ts()

    def add_admin(self, who: str) -> None:
        self.admins.add(who)

    def remove_admin(self, who: str) -> None:
        self.admins.discard(who)

    def grant(self, resource: str, to: str, valid_seconds: int, caller: str) -> None:
        """
        Otorga acceso a 'to' sobre 'resource' durante valid_seconds desde ahora.
        Solo un admin puede otorgar.
        """
        if caller not in self.admins:
            raise PermissionError("caller no es admin")
        if valid_seconds <= 0:
            raise ValueError("valid_seconds debe ser > 0")
        expiry = self._now() + float(valid_seconds)
        if resource not in self.grants:
            self.grants[resource] = {}
        self.grants[resource][to] = expiry

    def revoke(self, resource: str, to: str, caller: str) -> None:
        """
        Revoca acceso; solo admin puede revocar.
        """
        if caller not in self.admins:
            raise PermissionError("caller no es admin")
        if resource in self.grants and to in self.grants[resource]:
            del self.grants[resource][to]

    def has_access(self, resource: str, who: str) -> bool:
        """
        Devuelve True si 'who' tiene una grant no-expirada para 'resource'.
        """
        if resource not in self.grants:
            return False
        entry = self.grants[resource].get(who)
        if entry is None:
            return False
        if entry < self._now():
            # expired -> clean up
            del self.grants[resource][who]
            return False
        return True


class ActuatorPy:
    """
    Actuador que verifica permisos en AccessControlPy y emite eventos en Ledger.
    - actuate(resource, caller) -> Event (si permitido) o raises PermissionError.
    """
    def __init__(self, ledger: Ledger, access_control: AccessControlPy):
        self.ledger = ledger
        self.ac = access_control

    def actuate(self, resource: str, caller: str) -> Event:
        if not self.ac.has_access(resource, caller):
            # emitir evento de intento fallido también
            ev = self.ledger.emit_event("ActuationDenied", {"resource": resource, "caller": caller})
            raise PermissionError(f"Acceso denegado para {caller} sobre {resource} (event_emitted={ev.id})")
        # realizar "acción" (simulada) y emitir evento Actuated
        ev = self.ledger.emit_event("Actuated", {"resource": resource, "caller": caller})
        return ev


# ------------------ Demo ------------------ #
if __name__ == "__main__":
    print("CHAIN_SIM_PY DEMO\n------------------")
    ledger = Ledger()
    ac = AccessControlPy(initial_admins=["alice"])
    actuator = ActuatorPy(ledger, ac)

    # 1) Registrar una lectura de sensor (sensor1)
    print("Registrando lectura de sensor por 'sensor1'...")
    data = b"temp=22.5;unit=C"
    entry_id = ledger.register(submitter="sensor1", data_bytes=data, pointer="sensor1:seq:0001")
    print("Entry ID:", entry_id)
    e = ledger.get_entry(entry_id)
    print("Entry stored:", asdict(e) if e else None)

    # 2) Conceder permiso: alice (admin) concede a bob durante 60s para recurso 'door1'
    print("\nConcediendo permiso 'door1' a 'bob' por 60s (caller='alice')...")
    try:
        ac.grant(resource="door1", to="bob", valid_seconds=60, caller="alice")
        print("Grant aplicado.")
    except Exception as exc:
        print("Error applying grant:", exc)

    # 3) Actuador intenta accionar: primero bob (debe funcionar), luego eve (debe fallar)
    print("\nActuación por 'bob' sobre 'door1'...")
    try:
        ev = actuator.actuate(resource="door1", caller="bob")
        print("Actuated event:", asdict(ev))
    except PermissionError as pe:
        print("Permiso denegado para bob:", pe)

    print("\nActuación por 'eve' sobre 'door1' (sin permiso)...")
    try:
        ev2 = actuator.actuate(resource="door1", caller="eve")
        print("Actuated event:", asdict(ev2))
    except PermissionError as pe:
        print("Permiso denegado para eve:", pe)

    # 4) Mostrar eventos registrados
    print("\nEventos ledger:")
    for ev in ledger.get_events():
        print(asdict(ev))

    # 5) Exportar a JSON/CSV en el directorio actual
    out_json = "ledger_export.json"
    out_entries_csv = "ledger_entries.csv"
    out_events_csv = "ledger_events.csv"
    print(f"\nExportando ledger a {out_json} y CSVs {out_entries_csv}, {out_events_csv} ...")
    ledger.export_json(out_json)
    ledger.export_csv(out_entries_csv, out_events_csv)
    print("Export completado. Archivos creados (si permisos filesystem OK):")
    for p in (out_json, out_entries_csv, out_events_csv):
        print(" -", os.path.abspath(p))

    print("\nDemo completado.")
