"""ErrSight core — AST-based error path security analyzer."""
import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

SENSITIVE_RE = re.compile(
    r'(password|passwd|secret|token|api_key|apikey|access_key|'
    r'private_key|credential|ssn|social_security|credit_card|'
    r'card_number|cvv|pin_code|auth_token|session_id)',
    re.IGNORECASE,
)

LOG_PREFIXES = ('logging.', 'logger.', 'log.')
SINK_FUNCS = ('print', 'str', 'repr', 'format')


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    message: str


class _Visitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Finding] = []

    def _add(self, node: ast.AST, rule: str, sev: str, msg: str):
        self.findings.append(Finding(self.filename, node.lineno, rule, sev, msg))

    def _names(self, node: ast.AST) -> List[str]:
        out: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                out.append(child.id)
            elif isinstance(child, ast.Attribute):
                out.append(child.attr)
        return out

    def _func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            cur: ast.expr = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return '.'.join(reversed(parts))
        return ''

    def _is_sink(self, fname: str) -> bool:
        if fname in SINK_FUNCS:
            return True
        return any(fname.startswith(p) for p in LOG_PREFIXES)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self._add(node, 'BARE_EXCEPT', 'MEDIUM',
                      "Bare 'except:' catches all exceptions including "
                      "SystemExit/KeyboardInterrupt — may mask errors.")
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                fn = self._func_name(child)
                if self._is_sink(fn):
                    all_args = list(child.args) + [k.value for k in child.keywords]
                    for arg in all_args:
                        for name in self._names(arg):
                            if SENSITIVE_RE.search(name):
                                self._add(child, 'SENSITIVE_IN_LOG', 'HIGH',
                                          f"Sensitive '{name}' exposed via {fn}() in error handler.")
            if isinstance(child, ast.Return) and child.value:
                for name in self._names(child.value):
                    if SENSITIVE_RE.search(name):
                        self._add(child, 'SENSITIVE_IN_ERROR_RESPONSE', 'HIGH',
                                  f"Sensitive '{name}' returned in error handler — may leak to client.")
        self.generic_visit(node)


def scan_source(source: str, filename: str = '<string>') -> List[Finding]:
    tree = ast.parse(source, filename)
    v = _Visitor(filename)
    v.visit(tree)
    return v.findings


def scan_file(filepath: str) -> List[Finding]:
    source = Path(filepath).read_text(encoding='utf-8')
    return scan_source(source, filepath)
