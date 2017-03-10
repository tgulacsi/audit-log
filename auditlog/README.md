# Tamper-proof audit log

The biggest added value of this program is that not just that it hashes the records
with sha-512 and signs the hash with ed25519, but that it periodically writes the
time and hashes & signes the written data!

This way nobody can modify any data, AND nobody can delete records from the end:
they can't reproduce the ed25519 signs of the timestamps,
so the missing timestamps WILL reveal the tampering!
