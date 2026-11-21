# Test vectors

Files made by an earlier prototype of B-2FA, written in Python. The C++ tests open them to prove the
two editions read each other's files:

- `py_vault.b2fa`: a vault, master password `python-made-pass-123`, 4 accounts (TOTP, TOTP SHA256 with
  8 digits and a 60 s period, HOTP, Steam), accents and an emoji in a name.
- `py_export.2fas`: the same accounts as a 2FAS backup, password `python-export-pass`.
- `py_expected.json`: the codes the Python prototype computed for those accounts at fixed times.

They hold only made-up accounts. The reverse check (the Python prototype opening what C++ writes) was
done once by hand: `b2tests --emit DIR` writes `cpp_vault.b2fa` (`cpp-made-pass-1234`) and
`cpp_export.2fas` (`cpp-export-pass-12`).
