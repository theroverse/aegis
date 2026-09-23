import ast
from pathlib import Path

EXEMPT = {"src/aegis/system", "gui", "scripts"}
FORBIDDEN = {"comtypes", "winreg", "ctypes", "psutil"}
SRC = Path("src/aegis")


def _roots(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                yield node.module.split(".")[0]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "__import__" and node.args \
                and isinstance(node.args[0], ast.Constant):
            yield str(node.args[0].value).split(".")[0]


def test_motor_puro_nao_conhece_windows():
    viol = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.as_posix()
        if rel.startswith("src/aegis/system/") or rel.startswith("gui/") \
                or rel.startswith("scripts/"):
            continue
        roots = set(_roots(ast.parse(path.read_text(encoding="utf-8"))))
        bad = roots & FORBIDDEN
        if bad:
            viol.append(f"{rel}: {sorted(bad)}")
    assert viol == [], "fronteira de portabilidade violada:\n" + "\n".join(viol)
