from iroha import IrohaCrypto
private_key = IrohaCrypto.private_key()
public_key = IrohaCrypto.derive_public_key(private_key)

print(IrohaCrypto.derive_public_key(private_key))
private_key_file = f'admin@test1.priv'
public_key_file = f'admin@test1.pub'

with open(private_key_file, 'wb') as f:
    f.write(private_key)
with open(public_key_file, 'wb') as f:
    f.write(public_key)
