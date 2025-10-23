import pytest
from core.fw_sim import DeviceState, attack_default_creds, first_boot, verify_login, gen_keys, sign_image, verify_image

def test_attack_default_creds_true_initially_and_first_boot_protects():
ds = DeviceState()
# default is admin/admin
assert attack_default_creds(ds) is True
# apply first_boot with a new password
first_boot(ds, "MyS3cret!")
# after first_boot, admin_pass must be cleared and admin_hash set
assert ds.admin_pass == ""
assert ds.first_boot_done is True
assert ds.admin_hash != "" and len(ds.admin_hash) == 64
# attack_default_creds should now be False
assert attack_default_creds(ds) is False
# verify_login should work with new password
assert verify_login(ds, ds.admin_user, "MyS3cret!") is True
assert verify_login(ds, ds.admin_user, "wrong") is False
def test_sign_and_verify_image_ok():
priv_pem, pub_pem = gen_keys(key_size=2048)
image = b"TEST-FIRMWARE-BYTES"
sig = sign_image(priv_pem, image)
assert isinstance(sig, (bytes, bytearray))
# correct verification
assert verify_image(pub_pem, image, sig) is True
# tampered image fails verification
assert verify_image(pub_pem, b"TAMPERED", sig) is False
