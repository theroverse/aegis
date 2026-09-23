from __future__ import annotations

import subprocess
from typing import Iterable, List
from xml.etree import ElementTree as ET

from aegis.sources import BlockEvent, SourceUnavailable

CHANNEL = "Microsoft-Windows-Windows Firewall With Advanced Security\\Firewall"
_WECMD = "wevtutil"

# nomes de campos (inglês) do EventData -> nosso modelo
_KEYS = {
    "app": ("application path", "process path", "image"),
    "proto": ("protocol",),
    "src": ("source address", "source ip"),
    "dst": ("destination address", "destination ip"),
    "dport": ("destination port", "dest port"),
    "sport": ("source port", "src port"),
}
_PROTOS = {"6": "tcp", "17": "udp", "icmpv6": "icmpv6", "icmp": "icmp", "1": "icmp"}


def build_query_xml(minutes: int, event_ids: Iterable[int] = ()) -> str:
    ids = sorted({int(i) for i in event_ids if str(i).strip()})
    where = ""
    if ids:
        joined = " or ".join(f"EventID={i}" for i in ids)
        where = f"*[System[{joined}]]"
    return (
        "<QueryList>"
        f"<Query Id='0' Path='{CHANNEL}'>"
        f"<Select Path='{CHANNEL}'>{where or '*'}</Select>"
        "</Query></QueryList>"
    )


def _pick(fields, names):
    for k, v in fields.items():
        for n in names:
            if n in k.lower():
                return v
    return ""


def _is_private(ip: str) -> bool:
    if ip.startswith("172."):
        # 172.16.0.0/12 so: o segundo octeto deve estar em 16..31
        try:
            second = int(ip.split(".")[1])
        except (IndexError, ValueError):
            return False
        return 16 <= second <= 31
    return (ip.startswith("192.168.") or ip.startswith("10.")
            or ip.startswith("fe80") or ip.startswith("127."))


def parse_wevtutil_xml(xml_text: str) -> List[BlockEvent]:
    out: List[BlockEvent] = []
    root = ET.fromstring(xml_text)
    for ev in root.iter("Event"):
        fields = {d.get("Name", "").strip(): (d.text or "").strip()
                  for d in ev.iter("Data")}
        app = _pick(fields, _KEYS["app"])
        dport = _pick(fields, _KEYS["dport"])
        src = _pick(fields, _KEYS["src"])
        dst = _pick(fields, _KEYS["dst"])
        if not (app or (src and dst)):
            continue  # mudança de regra / outro tipo de evento
        proto_raw = _pick(fields, _KEYS["proto"]).lower()
        time_el = ev.find("./System/TimeCreated")
        ts = (time_el.get("SystemTime", "") if time_el is not None else "").replace("T", " ").split(".")[0]
        if _is_private(src):
            direction = "out"
        elif _is_private(dst):
            direction = "in"
        else:
            direction = ""
        out.append(BlockEvent(ts=ts, direction=direction,
                              protocol=_PROTOS.get(proto_raw, proto_raw),
                              src=src, dst=dst, port=dport,
                              program=app))
    return out


class EventLogBlockSource:
    def __init__(self, run=subprocess.run, minutes: int = 60,
                 event_ids: Iterable[int] = ()):
        self._run = run
        self._minutes = minutes
        self._ids = tuple(event_ids)
        self._last_ts = ""

    def new_events(self):
        q = build_query_xml(self._minutes, self._ids)
        try:
            proc = self._run([_WECMD, "qe", CHANNEL, f"/q:{q}", "/rd:true",
                              "/c:200", "/f:xml"],
                             capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=20)
        except subprocess.TimeoutExpired:
            # contrato da fonte (sources.py): so SourceUnavailable ou OSError escapam
            raise SourceUnavailable("wevtutil timeout")
        if proc.returncode != 0:
            return []  # canal inexistente/sem eventos: fonte fica "ok" mas vazia
        events = parse_wevtutil_xml(proc.stdout or "<Events/>")
        fresh = [e for e in events if e.ts > self._last_ts]
        if events:
            self._last_ts = max(e.ts for e in events)
        return fresh
