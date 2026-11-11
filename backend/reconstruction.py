"""Incident Reconstruction.

The Correlation Engine (``backend.correlation``) answers *how events are
connected*. Reconstruction answers the next question: *what happened, in
what order, and how sure are we?* — the question an investigator actually
has to defend.

It turns the raw events plus the correlation graph into an ordered list of
**stages**. A stage is one step of the attack narrative (recon, initial
access, execution, privilege escalation, ...). Every stage:

* names a MITRE ATT&CK technique, with the reason it was assigned;
* carries a confidence level that reflects how strong the evidence is;
* cites the concrete ``event_id`` values that back it (chain of custody),
  and the graph node ids to highlight.

Human-facing text (title, tactic, summary, the reason a technique was
assigned) is emitted in three languages — English, Russian, Kazakh — as
``{"en": ..., "ru": ..., "kz": ...}`` maps, so the one place that knows the
facts (counts, endpoints) also phrases them. MITRE technique ids and names
stay canonical English. The client picks a language; the evidence does not
change with it.

Nothing here invents evidence: a stage exists only because specific events
matched a documented signal. A detector that finds nothing emits nothing,
so an unknown incident simply yields a shorter story rather than a wrong
one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterable
from urllib.parse import unquote

LANGS = ("en", "ru", "kz")

# Ordered weakest -> strongest; used to roll up an overall verdict.
CONFIDENCE_ORDER = ["low", "medium", "high"]

# MITRE ATT&CK tactic names per language. Technique *names* stay English
# (their canonical form); tactics read more naturally localized.
TACTICS: dict[str, dict[str, str]] = {
    "reconnaissance": {
        "en": "Reconnaissance", "ru": "Разведка", "kz": "Барлау"},
    "initial_access": {
        "en": "Initial Access", "ru": "Первичный доступ",
        "kz": "Бастапқы қол жеткізу"},
    "persistence": {
        "en": "Persistence", "ru": "Закрепление", "kz": "Бекіну"},
    "execution": {
        "en": "Execution", "ru": "Выполнение", "kz": "Орындау"},
    "privilege_escalation": {
        "en": "Privilege Escalation", "ru": "Повышение привилегий",
        "kz": "Артықшылықтарды арттыру"},
    "command_and_control": {
        "en": "Command and Control", "ru": "Управление", "kz": "Басқару"},
}

# Per-stage static text. Tactic references a key in TACTICS. title / reason
# are fixed; summary carries {placeholders} filled from each detector's
# facts. MITRE id + technique name are canonical.
TEMPLATES: dict[str, dict[str, Any]] = {
    "vcs_exposure": {
        "tactic": "reconnaissance",
        "technique_id": "T1595.003",
        "technique": "Active Scanning: Wordlist Scanning",
        "title": {
            "en": "Source repository exposed",
            "ru": "Исходный код репозитория доступен",
            "kz": "Бастапқы код репозиторийі ашық"},
        "reason": {
            "en": "version-control paths were requested and served "
                  "(2xx/3xx), leaking server-side source",
            "ru": "запрашивались пути системы контроля версий и отдавались "
                  "(2xx/3xx), раскрывая серверный исходный код",
            "kz": "нұсқаларды басқару жүйесінің жолдары сұралып, қайтарылды "
                  "(2xx/3xx), серверлік бастапқы кодты әшкереледі"},
        "summary": {
            "en": "{n} request(s) to exposed VCS paths returned content "
                  "({paths}). Server-side source was retrievable, giving "
                  "the attacker app internals.",
            "ru": "{n} запрос(ов) к открытым путям VCS вернули содержимое "
                  "({paths}). Серверный код можно было скачать — "
                  "злоумышленник получил внутреннее устройство приложения.",
            "kz": "Ашық VCS жолдарына {n} сұрау мазмұн қайтарды ({paths}). "
                  "Серверлік кодты жүктеп алуға болатын — шабуылдаушы "
                  "қосымшаның ішкі құрылымын алды."},
    },
    "sql_injection": {
        "tactic": "initial_access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "title": {
            "en": "SQL injection against the application",
            "ru": "SQL-инъекция в приложение",
            "kz": "Қосымшаға SQL-инъекция"},
        "reason": {
            "en": "request parameters carried SQL syntax "
                  "(UNION/boolean/schema probes)",
            "ru": "в параметрах запросов был SQL-синтаксис "
                  "(UNION/булевы/зондирование схемы)",
            "kz": "сұрау параметрлерінде SQL синтаксисі болды "
                  "(UNION/логикалық/схеманы зерттеу)"},
        "summary": {
            "en": "{n} request(s) to {endpoints} contained SQL-injection "
                  "payloads{blind}",
            "ru": "{n} запрос(ов) к {endpoints} содержали SQL-инъекции{blind}",
            "kz": "{endpoints} мекенжайына {n} сұрауда SQL-инъекция "
                  "жүктемелері болды{blind}"},
    },
    "webshell_upload": {
        "tactic": "persistence",
        "technique_id": "T1505.003",
        "technique": "Server Software Component: Web Shell",
        "title": {
            "en": "Web shell uploaded",
            "ru": "Загружен веб-шелл",
            "kz": "Веб-шелл жүктелді"},
        "reason": {
            "en": "a file upload endpoint accepted a POST that was later "
                  "served as executable code (see execution stage)",
            "ru": "эндпоинт загрузки принял POST, который затем отдавался "
                  "как исполняемый код (см. этап выполнения)",
            "kz": "файл жүктеу эндпоинті POST қабылдады, ол кейін орындалатын "
                  "код ретінде берілді (орындау кезеңін қараңыз)"},
        "summary": {
            "en": "{n} upload POST(s) succeeded. Combined with the "
                  "execution stage this is an uploaded web shell.",
            "ru": "{n} POST-загрузок прошли успешно. Вместе с этапом "
                  "выполнения это загруженный веб-шелл.",
            "kz": "{n} жүктеу POST сәтті өтті. Орындау кезеңімен бірге бұл "
                  "жүктелген веб-шелл."},
    },
    "webshell_rce": {
        "tactic": "execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "title": {
            "en": "Remote code execution via web shell",
            "ru": "Удалённое выполнение кода через веб-шелл",
            "kz": "Веб-шелл арқылы қашықтан код орындау"},
        "reason": {
            "en": "the correlation engine tied spawned shell process(es) to "
                  "the HTTP request that carried their command",
            "ru": "движок корреляции связал порождённые процессы шелла с "
                  "HTTP-запросом, нёсшим их команду",
            "kz": "корреляция қозғалтқышы туындаған шелл процестерін олардың "
                  "командасын тасыған HTTP-сұраумен байланыстырды"},
        "summary": {
            "en": "{n} process(es) were executed through the web server and "
                  "attributed to attacker HTTP requests — commands ran on "
                  "the host as the web user.",
            "ru": "{n} процесс(ов) были выполнены через веб-сервер и "
                  "привязаны к HTTP-запросам злоумышленника — команды "
                  "выполнялись на хосте от имени веб-пользователя.",
            "kz": "{n} процесс веб-сервер арқылы орындалып, шабуылдаушының "
                  "HTTP-сұрауларына байланыстырылды — командалар хостта "
                  "веб-пайдаланушы атынан орындалды."},
    },
    "privilege_escalation": {
        "tactic": "privilege_escalation",
        "technique_id": "T1548",
        "technique": "Abuse Elevation Control Mechanism",
        "title": {
            "en": "Privilege escalation",
            "ru": "Повышение привилегий",
            "kz": "Артықшылықтарды арттыру"},
        "reason": {
            "en": "a command manipulated PATH around a privileged/SUID "
                  "helper to run attacker code with elevated rights",
            "ru": "команда подменила PATH вокруг привилегированного/"
                  "SUID-хелпера, чтобы выполнить код злоумышленника с "
                  "повышенными правами",
            "kz": "команда артықшылықты/SUID көмекшісінің айналасында "
                  "PATH-ты алмастырып, шабуылдаушы кодын жоғары "
                  "құқықтармен орындады"},
        "summary": {
            "en": "A process chain shows PATH manipulation around a "
                  "privileged helper ({helpers}), the hallmark of a SUID "
                  "PATH-hijack escalation.",
            "ru": "Цепочка процессов показывает подмену PATH вокруг "
                  "привилегированного хелпера ({helpers}) — признак "
                  "эскалации через SUID PATH-hijack.",
            "kz": "Процестер тізбегі артықшылықты көмекші ({helpers}) "
                  "айналасында PATH алмастыруын көрсетеді — SUID "
                  "PATH-hijack эскалациясының белгісі."},
    },
    "outbound_connection": {
        "tactic": "command_and_control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "title": {
            "en": "Outbound connection from a compromised process",
            "ru": "Исходящее соединение от скомпрометированного процесса",
            "kz": "Бұзылған процестен шығыс байланыс"},
        "reason": {
            "en": "a monitored process opened an outbound socket",
            "ru": "отслеживаемый процесс открыл исходящий сокет",
            "kz": "бақыланатын процесс шығыс сокет ашты"},
        "summary": {
            "en": "{n} outbound connection(s) to {dests} originated from "
                  "monitored processes.",
            "ru": "{n} исходящих соединений к {dests} исходили от "
                  "отслеживаемых процессов.",
            "kz": "{dests} мекенжайына {n} шығыс байланыс бақыланатын "
                  "процестерден шықты."},
    },
}

# "blind extraction" suffix for the SQLi summary, per language.
BLIND_SUFFIX = {
    "en": ", in a sustained pattern consistent with blind extraction.",
    "ru": ", устойчивым паттерном, характерным для слепого извлечения данных.",
    "kz": ", соқыр деректерді шығаруға тән тұрақты үлгімен.",
}
PLAIN_SUFFIX = {"en": ".", "ru": ".", "kz": "."}


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _http(event: dict) -> dict:
    return event.get("http") or {}


def _proc(event: dict) -> dict:
    return event.get("process") or {}


def _decoded_target(event: dict) -> str:
    """HTTP path with query, percent-decoded, lowercased — for matching."""
    return unquote((_http(event).get("path") or "")).lower()


def _localize(table: dict[str, str], **facts: Any) -> dict[str, str]:
    """Format a per-language template table with the given facts."""
    return {lang: table[lang].format(**facts) for lang in LANGS}


# --- detector signal tables ------------------------------------------------
SQLI_MARKERS = (
    "union select", "or 1=1", "or '1'='1", "case when", "information_schema",
    "sleep(", "benchmark(", " and (select", "waitfor delay", "' or ", "--",
)
VCS_MARKERS = ("/.git/", "/.svn/", "/.hg/")
WEBSHELL_CMD_PARAMS = ("c=", "cmd=", "exec=", "command=", "shell=")
EXECUTABLE_UPLOAD_EXT = (".phtml", ".php", ".php5", ".phar", ".jsp", ".asp", ".aspx")
PRIVESC_MARKERS = ("export path=", "path=/tmp", "path=.", "/usr/local/bin/")


Stage = dict[str, Any]
Detector = Callable[[list[dict], dict], list[Stage]]


def _mk_stage(
    *,
    key: str,
    confidence: str,
    summary: dict[str, str],
    evidence: list[str],
    nodes: list[str],
    time: str | None,
) -> Stage:
    tpl = TEMPLATES[key]
    return {
        "key": key,
        "tactic": TACTICS[tpl["tactic"]],
        "technique_id": tpl["technique_id"],
        "technique": tpl["technique"],
        "title": tpl["title"],
        "technique_reason": tpl["reason"],
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "nodes": nodes,
        "time": time,
    }


# --- detectors -------------------------------------------------------------
# Each detector receives the full event list and the correlation graph and
# returns zero or more stages. Detectors never raise on missing fields.


def _detect_vcs_exposure(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "http_request"
        and any(m in _decoded_target(e) for m in VCS_MARKERS)
        and (_http(e).get("status") or 0) < 400
    ]
    if not hits:
        return []
    hits.sort(key=lambda e: _ts(e["timestamp"]))
    paths = sorted({(_http(e).get("path") or "").split("?")[0] for e in hits})
    summary = _localize(
        TEMPLATES["vcs_exposure"]["summary"],
        n=len(hits), paths=", ".join(paths[:4]),
    )
    return [_mk_stage(
        key="vcs_exposure", confidence="high", summary=summary,
        evidence=[e["event_id"] for e in hits],
        nodes=[e["event_id"] for e in hits], time=hits[0]["timestamp"],
    )]


def _detect_sql_injection(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "http_request"
        and any(m in _decoded_target(e) for m in SQLI_MARKERS)
    ]
    if not hits:
        return []
    hits.sort(key=lambda e: _ts(e["timestamp"]))
    endpoints = sorted({(_http(e).get("path") or "").split("?")[0] for e in hits})
    # Many injection requests against one endpoint is the signature of
    # automated/blind extraction, not a stray match.
    blind = len(hits) >= 5
    suffix = BLIND_SUFFIX if blind else PLAIN_SUFFIX
    summary = {
        lang: TEMPLATES["sql_injection"]["summary"][lang].format(
            n=len(hits), endpoints=", ".join(endpoints[:3]), blind=suffix[lang],
        )
        for lang in LANGS
    }
    return [_mk_stage(
        key="sql_injection", confidence="high" if blind else "medium",
        summary=summary, evidence=[e["event_id"] for e in hits],
        nodes=[e["event_id"] for e in hits], time=hits[0]["timestamp"],
    )]


def _detect_webshell_upload(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "http_request"
        and (_http(e).get("method") or "") == "POST"
        and "upload" in _decoded_target(e)
        and (_http(e).get("status") or 0) < 400
    ]
    if not hits:
        return []
    hits.sort(key=lambda e: _ts(e["timestamp"]))
    summary = _localize(TEMPLATES["webshell_upload"]["summary"], n=len(hits))
    return [_mk_stage(
        key="webshell_upload", confidence="medium", summary=summary,
        evidence=[e["event_id"] for e in hits],
        nodes=[e["event_id"] for e in hits], time=hits[0]["timestamp"],
    )]


def _detect_webshell_rce(events: list[dict], graph: dict) -> list[Stage]:
    """RCE via web shell, proven by a correlation spawned_by edge.

    This is the strongest kind of finding: not a pattern in a log, but a
    process the graph attributes to a specific HTTP request.
    """
    node_by_id = {n["id"]: n for n in graph.get("nodes", [])}
    spawned = [e for e in graph.get("edges", []) if e["kind"] == "spawned_by"]
    if not spawned:
        return []

    evidence: list[str] = []
    nodes: list[str] = []
    first_time: str | None = None
    served_shell = False

    for edge in spawned:
        req = node_by_id.get(edge["source"])
        proc = node_by_id.get(edge["target"])
        if req is None or proc is None:
            continue
        target = unquote((req.get("label") or "")).lower()
        if any(ext in target for ext in EXECUTABLE_UPLOAD_EXT):
            served_shell = True
        for nid in (edge["source"], edge["target"]):
            if nid not in nodes:
                nodes.append(nid)
                evidence.append(nid)
        ts = proc.get("timestamp")
        if ts and (first_time is None or _ts(ts) < _ts(first_time)):
            first_time = ts

    if not nodes:
        return []

    # "carried the command" edges are the high-confidence ones.
    carried = any("carried the command" in e["reason"] for e in spawned)
    confidence = "high" if (carried or served_shell) else "medium"
    summary = _localize(TEMPLATES["webshell_rce"]["summary"], n=len(spawned))
    return [_mk_stage(
        key="webshell_rce", confidence=confidence, summary=summary,
        evidence=evidence, nodes=nodes, time=first_time,
    )]


def _detect_privilege_escalation(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "process_created"
        and any(m in (_proc(e).get("command_line") or "").lower()
                for m in PRIVESC_MARKERS)
    ]
    # Also catch a process that visibly changed euid to root downstream of a
    # web-spawned shell, named like a backup/SUID helper.
    suid_like = [
        e for e in events
        if e["event_type"] == "process_created"
        and (_proc(e).get("name") or "") in {"system-backup", "backup", "tar"}
    ]
    if not hits and not suid_like:
        return []
    chain = {e["event_id"]: e for e in hits + suid_like}
    ordered = sorted(chain.values(), key=lambda e: _ts(e["timestamp"]))
    helpers = ", ".join(sorted({(_proc(e).get("name") or "?") for e in ordered}))
    summary = _localize(
        TEMPLATES["privilege_escalation"]["summary"], helpers=helpers)
    return [_mk_stage(
        key="privilege_escalation", confidence="medium", summary=summary,
        evidence=[e["event_id"] for e in ordered],
        nodes=[e["event_id"] for e in ordered], time=ordered[0]["timestamp"],
    )]


def _detect_outbound(events: list[dict], graph: dict) -> list[Stage]:
    hits = [e for e in events if e["event_type"] == "network_connection"]
    if not hits:
        return []
    hits.sort(key=lambda e: _ts(e["timestamp"]))
    dests = sorted({
        f"{(e.get('network') or {}).get('destination_ip')}:"
        f"{(e.get('network') or {}).get('destination_port')}"
        for e in hits
    })
    summary = _localize(
        TEMPLATES["outbound_connection"]["summary"],
        n=len(hits), dests=", ".join(dests[:3]),
    )
    return [_mk_stage(
        key="outbound_connection", confidence="low", summary=summary,
        evidence=[e["event_id"] for e in hits],
        nodes=[e["event_id"] for e in hits], time=hits[0]["timestamp"],
    )]


# Detectors run in a fixed order; the final stage order is by evidence time.
DETECTORS: list[Detector] = [
    _detect_vcs_exposure,
    _detect_sql_injection,
    _detect_webshell_upload,
    _detect_webshell_rce,
    _detect_privilege_escalation,
    _detect_outbound,
]


def _overall_confidence(stages: list[Stage]) -> str | None:
    if not stages:
        return None
    return max(
        (s["confidence"] for s in stages),
        key=CONFIDENCE_ORDER.index,
    )


def reconstruct(events: Iterable[dict], graph: dict) -> dict[str, Any]:
    """Build an ordered, evidence-linked incident narrative.

    ``events`` are normalized events; ``graph`` is the output of
    ``backend.correlation.correlate``. Returns::

        {
          "stages": [ {... , "order": int}, ... ],   # chronological
          "overall_confidence": "high" | ... | None,
          "stage_count": int,
        }

    Each stage's ``title``, ``tactic``, ``technique_reason`` and ``summary``
    are ``{"en","ru","kz"}`` maps; ``technique``/``technique_id`` are
    canonical English.
    """
    events = list(events)

    stages: list[Stage] = []
    for detector in DETECTORS:
        stages.extend(detector(events, graph))

    # Order the narrative by when its evidence first appears.
    stages.sort(key=lambda s: _ts(s["time"]) if s["time"] else datetime.max)
    for i, stage in enumerate(stages, start=1):
        stage["order"] = i

    return {
        "stages": stages,
        "overall_confidence": _overall_confidence(stages),
        "stage_count": len(stages),
    }
