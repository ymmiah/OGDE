"""Legacy ``python -m odge`` entrypoint. The canonical module is ``ogde``."""
from ogde.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
