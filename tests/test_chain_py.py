import pytest
from core.chain_sim_py import Ledger, AccessControlPy, ActuatorPy

def test_ledger_register_creates_entry_and_retrievable():
ledger = Ledger()
data = b"payload:42"
submitter = "deviceA"
pointer = "deviceA:001"
entry_id = ledger.register(submitter=submitter, data_bytes=data, pointer=pointer)
assert isinstance(entry_id, str) and len(entry_id) == 64
entry = ledger.get_entry(entry_id)
assert entry is not None
assert entry.submitter == submitter
assert entry.data_hex == data.hex()
# all_entries should include this entry
all_e = ledger.all_entries()
assert any(e.id == entry_id for e in all_e)

def test_grant_and_actuate_flow_for_gateway():
ledger = Ledger()
ac = AccessControlPy(initial_admins=["admin"])
actuator = ActuatorPy(ledger, ac)
resource = "doorX"
gateway = "gateway1"
# initially no access
assert ac.has_access(resource, gateway) is False

# admin grants access for 10 seconds
ac.grant(resource=resource, to=gateway, valid_seconds=10, caller="admin")
assert ac.has_access(resource, gateway) is True

# actuator should allow gateway to actuate
ev = actuator.actuate(resource=resource, caller=gateway)
assert ev is not None
assert ev.kind == "Actuated"

# revoke and ensure subsequent actuation fails
ac.revoke(resource=resource, to=gateway, caller="admin")
assert ac.has_access(resource, gateway) is False
with pytest.raises(PermissionError):
    actuator.actuate(resource=resource, caller=gateway)
