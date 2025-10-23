# core/mqtt_sim.py
# Simulador local de broker MQTT basado en memoria (colas por topic).
# Todo es local-only: sin sockets, sin hilos, completamente determinista.

from __future__ import annotations
from collections import deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, List, Any
import time
import json


@dataclass
class Message:
    """Mensaje almacenado en la cola de un topic (incluye timestamp)."""
    timestamp: float
    payload: Any

    def to_dict(self):
        return {"ts": self.timestamp, "payload": self.payload}


class BrokerMem:
    """
    Broker en memoria que mantiene una cola por topic.
    - Cada cola es una deque con tope opcional (por defecto 1000 mensajes).
    - publish(topic, payload) almacena un Message.
    - subscribe(topic) devuelve la cola (Deque[Message]) para lectura local.
    """
    def __init__(self, maxlen: int = 1000):
        self.topics: Dict[str, Deque[Message]] = {}
        self.maxlen = maxlen

    def _ensure_topic(self, topic: str) -> Deque[Message]:
        if topic not in self.topics:
            self.topics[topic] = deque(maxlen=self.maxlen)
        return self.topics[topic]

    def publish(self, topic: str, payload: Any) -> None:
        """
        Publica un payload en el topic (almacena un Message).
        No entrega activa a "clientes"; los subscriptores leen la cola localmente.
        """
        q = self._ensure_topic(topic)
        msg = Message(timestamp=time.time(), payload=payload)
        q.append(msg)

    def subscribe(self, topic: str) -> Deque[Message]:
        """
        Devuelve la cola local asociada al topic.
        El llamador puede inspeccionarla o leer mensajes de ella directamente.
        """
        return self._ensure_topic(topic)

    def topics_list(self) -> List[str]:
        """Lista de topics conocidos."""
        return list(self.topics.keys())

    def dump_topic(self, topic: str) -> List[Dict]:
        """Devuelve una representación serializable del contenido del topic."""
        q = self.topics.get(topic, deque())
        return [m.to_dict() for m in q]


# ------------------ Utilidades externas (attaques/inspección locales) ------------------ #

def sniff(queue: Deque[Message], maxn: int = 10) -> List[Dict]:
    """
    Devuelve los últimos `maxn` mensajes de la cola sin consumirlos.
    Resultado en formato dict {'ts':..., 'payload':...}, ordenados de más antiguo a más reciente.
    """
    if maxn <= 0:
        return []
    n = min(len(queue), maxn)
    # tomar los últimos n elementos
    tail = list(queue)[-n:]
    return [m.to_dict() for m in tail]


def spoof(broker: BrokerMem, topic: str, fake_payload: Any) -> Message:
    """
    Inyecta un mensaje falso directamente en la cola del broker para `topic`.
    Retorna el Message inyectado.
    """
    q = broker.subscribe(topic)
    msg = Message(timestamp=time.time(), payload=fake_payload)
    q.append(msg)
    return msg


def mitm_publish(broker: BrokerMem, topic: str, payload: Any, modifier=None) -> Message:
    """
    'Man-in-the-middle' local: modifica el payload antes de almacenarlo.
    - modifier: función opcional payload->payload. Si no se da, se aplica una modificación por defecto.
    Retorna el Message publicado (con payload modificado).
    """
    if modifier is None:
        # modificación por defecto: envolver en estructura que indica MITM y añade huella simple
        try:
            # intentar obtener una representación estable del payload
            repr_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        except Exception:
            repr_payload = repr(payload)
        # huella simple: sha1 parcial
        import hashlib
        h = hashlib.sha1(repr_payload.encode("utf-8")).hexdigest()[:8]
        new_payload = {"original": payload, "mitm_note": f"tampered_by_local_mitm_{h}"}
    else:
        new_payload = modifier(payload)

    q = broker.subscribe(topic)
    msg = Message(timestamp=time.time(), payload=new_payload)
    q.append(msg)
    return msg


# ------------------ Demo en __main__ ------------------ #
if __name__ == "__main__":
    print("Demo BrokerMem / sniff / spoof / mitm (local-only)\n")

    b = BrokerMem(maxlen=50)

    # Publicar algunos mensajes legítimos
    b.publish("sensors/temp", {"t": 21.5, "unit": "C"})
    b.publish("sensors/temp", {"t": 21.7, "unit": "C"})
    b.publish("sensors/humidity", {"h": 45})

    # Suscribirse (obtener la cola local)
    q_temp = b.subscribe("sensors/temp")
    q_h = b.subscribe("sensors/humidity")

    print("Topics:", b.topics_list())
    print("\nContenido inicial sensors/temp (sniff 5):")
    for m in sniff(q_temp, maxn=5):
        print(m)

    # SPOOF: inyectar mensaje falso
    print("\n-- Inyectando spoof en sensors/temp --")
    spoof_msg = spoof(b, "sensors/temp", {"t": 99.9, "unit": "C", "note": "spoofed"})
    print("Spoofed message stored:", spoof_msg.to_dict())

    print("\nContenido sensors/temp tras spoof (sniff 10):")
    for m in sniff(q_temp, maxn=10):
        print(m)

    # MITM publish: publica pero modifica payload antes de almacenar
    print("\n-- MITM publish en sensors/humidity --")
    mitm_msg = mitm_publish(b, "sensors/humidity", {"h": 42}, modifier=None)
    print("MITM message stored:", mitm_msg.to_dict())

    print("\nContenido sensors/humidity (sniff 10):")
    for m in sniff(q_h, maxn=10):
        print(m)

    # Demostrar que publish normal sigue funcionando
    print("\n-- Publicación normal en sensors/temp --")
    b.publish("sensors/temp", {"t": 22.0, "unit": "C"})
    print("Últimos 5 en sensors/temp:")
    for m in sniff(q_temp, maxn=5):
        print(m)

    print("\nDemo completado.")
