# Kernel signing boundary

The committed kernel configuration names the public module-signing certificate,
but Git contains no private key material. Gate 01 creates one development
identity locally and supplies that same identity to both clean builders so that
their RSA module signatures are comparable.

The private key is mounted read-only for the build. It never enters an SRPM,
RPM, OCI layer, QCOW2 image, log, or evidence bundle. The public certificate is
included in the kernel trust set and in Gate 01 evidence.

Gate 01 does not PE-sign the kernel and makes no claim that firmware or shim
will accept it under Secure Boot. Gate 02 replaces this development identity
with controlled kernel and module signing and records MOK enrollment evidence.
