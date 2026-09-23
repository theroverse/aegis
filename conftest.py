import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# Pina o pacote src/aegis em sys.modules ANTES da coleta: ao importar o
# pacote `tests`, o pytest re-prepende a raiz do repo no sys.path, e o
# launcher aegis.py da raiz sombrearia o pacote (`'aegis' is not a package`).
import aegis  # noqa: E402,F401
