"""Separate entrypoint for the fixed, publicly known synthetic regtest key."""
import sys

from claim import main

if __name__ == "__main__":
    sys.exit(main(synthetic=True))
