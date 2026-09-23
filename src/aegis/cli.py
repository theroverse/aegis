from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _offline_engine(entry: Path):
    """Motor com fakes embutidos: serve smoke/CI em qualquer SO sem tocar
    no sistema real. Os fakes vivem em tests/fakes.py e sao reusados aqui
    so no modo --offline."""
    p = str(entry.parent / "tests")
    if p not in sys.path:
        sys.path.insert(0, p)
    from fakes import FakeBlockSource, FakeConnSource, FakeFirewallProvider
    from aegis.engine import Engine
    prov = FakeFirewallProvider()
    prov.inject(__import__("aegis.firewall", fromlist=["RuleInfo"]).RuleInfo(
        name="Aegis · exemplo", direction="in", action="allow",
        protocol="tcp", local_ports="8080", profiles=("private",),
        enabled=True, program="C:\\demo.exe", built_in=False))
    return Engine(provider=prov, conn_source=FakeConnSource(),
                  block_source=FakeBlockSource(batches=[]),
                  runner=lambda req: {"ok": False, "motivo": "offline"},
                  anchor=entry)


def _windows_engine(entry: Path):
    from aegis.system.connections import active_connections
    from aegis.system.eventlog import EventLogBlockSource
    from aegis.system.firewall_api import ComFirewallProvider
    from aegis.system.pfirewall import PfirewallSource
    from aegis.engine import Engine
    from aegis.settings import Settings, state_dir

    prov = ComFirewallProvider()
    st = state_dir(entry)
    settings = Settings(st / "config.json")
    block = EventLogBlockSource(
        event_ids=settings.get("firewall.bloqueios_event_ids") or ())
    offline_log = PfirewallSource(
        Path("C:/Windows/System32/LogFiles/Firewall/pfirewall.log"))

    class _Composite:
        def new_events(self):
            return list(block.new_events()) + list(offline_log.new_events())

    from aegis.system.elevate import ElevatedRunner
    helper = entry.parent / "AegisApply.exe"
    if not helper.exists():
        helper = entry.parent / "scripts" / "aegis_apply.py"
    return Engine(provider=prov,
                  conn_source=type("C", (), {"connections": lambda self: active_connections()})(),
                  block_source=_Composite(),
                  runner=ElevatedRunner(helper, st),
                  anchor=entry, settings=settings)


def main(entry: Path, argv=None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    parser.add_argument("--offline", action="store_true",
                        help="motor com fakes (smoke/CI, nunca toca o sistema)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("status")
    sub.add_parser("rules")
    p_draft = sub.add_parser("ask-ai")
    p_draft.add_argument("--program", required=True)
    p_draft.add_argument("--direction", default="in")
    p_draft.add_argument("--protocol", default="tcp")
    p_draft.add_argument("--port", required=True)
    p_ingest = sub.add_parser("ingest")
    p_ingest.add_argument("json_file")
    p_approve = sub.add_parser("approve")
    p_approve.add_argument("draft_id")
    p_approve.add_argument("--replace", action="store_true")
    sub.add_parser("audit")
    args = parser.parse_args(argv)

    engine = _offline_engine(entry) if args.offline else _windows_engine(entry)

    def out(obj):
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))

    if args.cmd == "status":
        s = engine.monitor.snapshot()
        out({"regras": len(engine.provider.list_rules()),
             "conexoes": len(s["conexoes"]),
             "bloqueios_no_anel": len(s["bloqueios"]),
             "estado_bloqueios": s["estado_bloqueios"],
             "revisoes_pendentes": len(engine.drafts.all("pendente"))})
    elif args.cmd == "rules":
        out([r.__dict__ for r in engine.provider.list_rules()])
    elif args.cmd == "ask-ai":
        print(engine.ask_ai({"program": args.program,
                             "direction": args.direction,
                             "protocol": args.protocol, "port": args.port,
                             "origin": "pedido manual", "profile": "private",
                             "existing": []}))
    elif args.cmd == "ingest":
        added = engine.ingest_ai_response(
            Path(args.json_file).read_text(encoding="utf-8-sig"))
        out([d.draft_id for d in added])
    elif args.cmd == "approve":
        out(engine.approve_and_apply(args.draft_id, replace=args.replace))
    elif args.cmd == "audit":
        out(engine.audit.read())
    else:
        parser.print_help()
    return 0
