# 🚀 Release Notes – sophomorix 7.4

**Package version:** 7.4.1 – 7.4.5

---

## 📋 Overview

A much lighter cycle for the core sophomorix scripts than for the rest of
the stack — most of the 7.4 work happened in the layers above it
(`linuxmuster-tools`, the API, the webui and the CLI).

---

## 🏫 Schoolclass subgroups

- `sophomorix-class` cleans up the `<class>-teachers` / `-students` /
  `-parents` subgroups when a schoolclass is killed: it used to delete the
  schoolclass group only and leave them, and the OU of the class, behind.
- The members of all the subgroups are updated, not only the teachers one.
- `sophomorix-class` uses the new `lmncli` parameters.

---

## 🔧 Other changes

- Configurable login-name format: separator, regex and maximum length can
  now be set instead of being hardcoded (@hermanntoast).
- Added missing Samba dependencies.
- Dice passwords now use the Debian `diceware` package instead of a pip
  install. `diceware` is a proper dependency of `sophomorix-samba`, the
  `pip install diceware` in `sophomorix-postinst` is gone, and the postinst
  removes the obsolete pip copy under `/usr/local` — it shadowed
  `/usr/bin/diceware` in the `PATH` and was never upgraded. The hardcoded
  `/usr/local/lib/python3.10/...` checks on the binary and on the wordlist
  are dropped: those paths depend on the Python version of the distribution,
  and `diceware` itself reports a missing binary or an unknown wordlist
  through its return code.

---

Author: Arnaud Kientz
Co-Author: Claude
