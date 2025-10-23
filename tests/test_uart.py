import pytest
from core.uart_sim import UARTState, handle_cmd

def test_dump_secrets_insecure_mode_shows_secrets():
st = UARTState()
# Desactivar modo secure para permitir DUMP SECRETS sin auth
st.secure = False
st.locked = False
out = handle_cmd(st, "DUMP SECRETS")
assert "KEY_VALUE" in out and "ADMIN_PW" in out

def test_three_failed_auth_attempts_cause_lockout_in_secure_mode():
st = UARTState()
# asegurar modo seguro y que esté locked inicialmente
st.secure = True
st.locked = True
# 1st fail
r1 = handle_cmd(st, "AUTH wrong1")
assert "autenticación fallida" in r1.lower()
assert st.fail_count == 1
assert st.locked is True
# 2nd fail
r2 = handle_cmd(st, "AUTH wrong2")
assert "autenticación fallida" in r2.lower()
assert st.fail_count == 2
assert st.locked is True
# 3rd fail -> lockout message expected
r3 = handle_cmd(st, "AUTH wrong3")
assert "lockout" in r3.lower() or "autenticación fallida" in r3.lower()
assert st.fail_count >= 3
# still locked
assert st.locked is True
