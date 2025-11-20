"""Compatibility shim: keep old filename but delegate to `covid_19.py`."""

from covid_19 import main


if __name__ == "__main__":
    main()