from core.mqtt_sim import BrokerMem, sniff, spoof, mitm_publish
import json

def test_publish_spoof_mitm_and_sniff_behaviour():
broker = BrokerMem(maxlen=50)
topic = "test/topic"
# publish normal message (dict)
payload1 = {"t": 21}
broker.publish(topic, payload1)

# sniff should show this message
q = broker.subscribe(topic)
s1 = sniff(q, maxn=10)
assert len(s1) >= 1
assert any(m["payload"] == payload1 for m in s1)

# spoof: inject a fake message
fake = {"t": 99, "spoofed": True}
spoofed_msg = spoof(broker, topic, fake)
assert spoofed_msg.payload == fake

# verify sniff includes spoofed message at the tail
s2 = sniff(q, maxn=10)
assert any(m["payload"] == fake for m in s2)

# mitm_publish: will modify payload before storing
original = {"h": 40}
mitm_msg = mitm_publish(broker, topic, original)
# mitm default wraps original into dict with 'original' key
assert isinstance(mitm_msg.payload, dict)
assert "original" in mitm_msg.payload
assert mitm_msg.payload["original"] == original

# final sniff should contain at least one MITM-modified message
s3 = sniff(q, maxn=20)
assert any(isinstance(m["payload"], dict) and "mitm_note" in m["payload"] for m in s3)
