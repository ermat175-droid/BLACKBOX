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

from backend.correlation import WEB_SERVER_NAMES

LANGS = ("en", "ru", "kz")

# Ordered weakest -> strongest; used to roll up an overall verdict.
CONFIDENCE_ORDER = ["low", "medium", "high"]

# Kill-chain order of tactics. Stages are told as a story in this order
# (with evidence time as a tiebreaker) rather than by raw timestamp, because
# receipt-time stamping across two collectors is too coarse to trust for
# ordering a sub-second attack.
TACTIC_ORDER = [
    "reconnaissance", "initial_access", "persistence", "execution",
    "privilege_escalation", "collection", "command_and_control",
]

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
    "collection": {
        "en": "Collection", "ru": "Сбор данных", "kz": "Деректерді жинау"},
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
    "ssti": {
        "tactic": "initial_access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "title": {
            "en": "Server-side template injection",
            "ru": "SSTI — внедрение шаблона на сервере",
            "kz": "SSTI — серверлік шаблон инъекциясы"},
        "reason": {
            "en": "request parameters carried template-injection syntax "
                  "({{…}}, __globals__, __import__) that reaches language internals",
            "ru": "в параметрах запроса был синтаксис внедрения шаблона "
                  "({{…}}, __globals__, __import__), дотягивающийся до внутренностей языка",
            "kz": "сұрау параметрлерінде тіл ішкі механизмдеріне жететін "
                  "шаблон инъекциясының синтаксисі болды ({{…}}, __globals__, __import__)"},
        "summary": {
            "en": "{n} request(s) to {endpoints} carried server-side "
                  "template-injection payloads reaching language internals "
                  "(a path to code execution).",
            "ru": "{n} запрос(ов) к {endpoints} несли SSTI-пейлоады, "
                  "дотягивающиеся до внутренностей языка (путь к выполнению кода).",
            "kz": "{endpoints} мекенжайына {n} сұрау тіл ішкі механизмдеріне "
                  "жететін SSTI-пейлоадтарды тасыды (код орындауға жол)."},
    },
    "webshell_rce": {
        "tactic": "execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "title": {
            "en": "Remote code execution via the web application",
            "ru": "Удалённое выполнение кода через веб-приложение",
            "kz": "Веб-қосымша арқылы қашықтан код орындау"},
        "reason": {
            "en": "the web server spawned OS shells — a web app running "
                  "/bin/sh is the signature of RCE; linked to the request "
                  "when correlation found one",
            "ru": "веб-сервер породил системные shell — веб-приложение, "
                  "запускающее /bin/sh, это признак RCE; связано с запросом, "
                  "если корреляция его нашла",
            "kz": "веб-сервер жүйелік shell туғызды — /bin/sh іске қосатын "
                  "веб-қосымша RCE белгісі; корреляция тапқанда сұраумен "
                  "байланыстырылды"},
        "summary": {
            "en": "{n} shell process(es) were spawned by the web server — "
                  "the application executed attacker commands on the host.",
            "ru": "{n} shell-процесс(ов) были порождены веб-сервером — "
                  "приложение выполняло команды злоумышленника на хосте.",
            "kz": "{n} shell процесс веб-сервермен туғызылды — қосымша "
                  "шабуылдаушы командаларын хостта орындады."},
    },
    "sensitive_access": {
        "tactic": "collection",
        "technique_id": "T1005",
        "technique": "Data from Local System",
        "title": {
            "en": "Sensitive file read",
            "ru": "Чтение чувствительного файла",
            "kz": "Құпия файлды оқу"},
        "reason": {
            "en": "a process read a protected path (/root, /etc/shadow)",
            "ru": "процесс прочитал защищённый путь (/root, /etc/shadow)",
            "kz": "процесс қорғалған жолды оқыды (/root, /etc/shadow)"},
        "summary": {
            "en": "{n} process(es) read protected files ({paths}) — the "
                  "attacker reached secrets such as the flag or password hashes.",
            "ru": "{n} процесс(ов) прочитали защищённые файлы ({paths}) — "
                  "злоумышленник добрался до секретов (флаг, хеши паролей).",
            "kz": "{n} процесс қорғалған файлдарды оқыды ({paths}) — "
                  "шабуылдаушы құпияларға жетті (флаг, пароль хэштері)."},
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
            "en": "a SUID/privileged helper, a preserved-privilege shell "
                  "(-p), or a PATH hijack ran code with elevated rights",
            "ru": "SUID/привилегированный хелпер, shell с сохранением прав "
                  "(-p) или подмена PATH выполнили код с повышенными правами",
            "kz": "SUID/артықшылықты көмекші, құқықты сақтайтын shell (-p) "
                  "немесе PATH алмастыру кодты жоғары құқықтармен орындады"},
        "summary": {
            "en": "A process chain shows privilege escalation via {helpers} "
                  "(SUID helper / preserved-privilege shell / PATH hijack).",
            "ru": "Цепочка процессов показывает повышение привилегий через "
                  "{helpers} (SUID-хелпер / shell с -p / подмена PATH).",
            "kz": "Процестер тізбегі {helpers} арқылы артықшылықтарды "
                  "арттыруды көрсетеді (SUID көмекші / -p shell / PATH алмастыру)."},
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

# Server-side template injection. STRONG markers reach language internals
# (near-certain RCE); the weak ones are just template syntax.
SSTI_MARKERS = (
    "{{", "}}", "{%", "${", "<%=", "#{",
    "__class__", "__globals__", "__import__", "__builtins__",
    "__subclasses__", "os.system", "popen(", "subprocess",
)
SSTI_STRONG = (
    "__globals__", "__import__", "__builtins__", "__subclasses__",
    "os.system", "popen(", "subprocess",
)

# Shells an application should never normally exec — a web server spawning
# one of these is the signature of remote code execution.
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh", "ash"}

# Protected paths whose read means the attacker reached secrets.
SENSITIVE_PATHS = ("/root/", "/etc/shadow", "/etc/sudoers")


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


def _detect_ssti(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "http_request"
        and any(m in _decoded_target(e) for m in SSTI_MARKERS)
    ]
    if not hits:
        return []
    hits.sort(key=lambda e: _ts(e["timestamp"]))
    endpoints = sorted({(_http(e).get("path") or "").split("?")[0] for e in hits})
    strong = any(
        any(m in _decoded_target(e) for m in SSTI_STRONG) for e in hits
    )
    summary = _localize(
        TEMPLATES["ssti"]["summary"],
        n=len(hits), endpoints=", ".join(endpoints[:3]),
    )
    return [_mk_stage(
        key="ssti", confidence="high" if strong else "medium", summary=summary,
        evidence=[e["event_id"] for e in hits],
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
    """RCE: a web server spawned OS shells.

    Primarily process-based — a web app running /bin/sh is the signature of
    code execution, and it is caught from process telemetry even when no
    HTTP log was available. When the correlation graph also tied a shell to
    an HTTP request, that request is added as chain-of-custody and raises
    confidence.
    """
    shells = [
        e for e in events
        if e["event_type"] == "process_created"
        and e["process"].get("parent_name") in WEB_SERVER_NAMES
        and (e["process"].get("name") or "") in SHELL_NAMES
    ]
    if not shells:
        return []
    shells.sort(key=lambda e: _ts(e["timestamp"]))

    evidence = [e["event_id"] for e in shells]
    nodes = list(evidence)

    # Enrich with correlated requests (spawned_by edges), for custody + confidence.
    node_by_id = {n["id"]: n for n in graph.get("nodes", [])}
    spawned = [e for e in graph.get("edges", []) if e["kind"] == "spawned_by"]
    served_shell = False
    for edge in spawned:
        req = node_by_id.get(edge["source"])
        if req is None:
            continue
        if any(ext in unquote((req.get("label") or "")).lower()
               for ext in EXECUTABLE_UPLOAD_EXT):
            served_shell = True
        if edge["source"] not in nodes:
            nodes.append(edge["source"])
            evidence.append(edge["source"])

    carried = any("carried the command" in e["reason"] for e in spawned)
    confidence = "high" if (carried or served_shell) else "medium"
    summary = _localize(TEMPLATES["webshell_rce"]["summary"], n=len(shells))
    return [_mk_stage(
        key="webshell_rce", confidence=confidence, summary=summary,
        evidence=evidence, nodes=nodes, time=shells[0]["timestamp"],
    )]


SUID_HELPER_NAMES = {"system-backup", "backup", "tar", "rootbash"}


def _is_privesc(event: dict) -> bool:
    p = _proc(event)
    name = (p.get("name") or "")
    cmd = (p.get("command_line") or "").lower()
    if name in SUID_HELPER_NAMES:
        return True
    if any(m in cmd for m in PRIVESC_MARKERS):
        return True
    # A shell invoked with -p keeps SUID privileges (classic root shell).
    if name in SHELL_NAMES and (" -p " in f" {cmd} " or cmd.endswith(" -p")):
        return True
    # A shell binary planted in a world-writable dir and run.
    if any(d in cmd for d in ("/tmp/", "/var/tmp/", "/dev/shm/")) and \
            any(s in cmd for s in ("rootbash", "bash", "/sh ", "/sh\"")):
        return True
    # Making a file SUID.
    if "chmod" in cmd and any(s in cmd for s in ("+s", "u+s", "4755", "6755", "4777")):
        return True
    return False


def _detect_privilege_escalation(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "process_created" and _is_privesc(e)
    ]
    if not hits:
        return []
    ordered = sorted(hits, key=lambda e: _ts(e["timestamp"]))
    helpers = ", ".join(sorted({(_proc(e).get("name") or "?") for e in ordered}))
    summary = _localize(
        TEMPLATES["privilege_escalation"]["summary"], helpers=helpers)
    return [_mk_stage(
        key="privilege_escalation", confidence="medium", summary=summary,
        evidence=[e["event_id"] for e in ordered],
        nodes=[e["event_id"] for e in ordered], time=ordered[0]["timestamp"],
    )]


def _detect_sensitive_access(events: list[dict], graph: dict) -> list[Stage]:
    hits = [
        e for e in events
        if e["event_type"] == "process_created"
        and any(p in (_proc(e).get("command_line") or "") for p in SENSITIVE_PATHS)
    ]
    if not hits:
        return []
    ordered = sorted(hits, key=lambda e: _ts(e["timestamp"]))
    paths = sorted({
        p for e in ordered for p in SENSITIVE_PATHS
        if p in (_proc(e).get("command_line") or "")
    })
    summary = _localize(
        TEMPLATES["sensitive_access"]["summary"],
        n=len(ordered), paths=", ".join(paths),
    )
    return [_mk_stage(
        key="sensitive_access", confidence="high", summary=summary,
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
    _detect_ssti,
    _detect_webshell_upload,
    _detect_webshell_rce,
    _detect_privilege_escalation,
    _detect_sensitive_access,
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

    # Tell the story in kill-chain order; evidence time breaks ties.
    def _order_key(s: Stage):
        tactic_key = TEMPLATES[s["key"]]["tactic"]
        rank = (TACTIC_ORDER.index(tactic_key)
                if tactic_key in TACTIC_ORDER else len(TACTIC_ORDER))
        return (rank, _ts(s["time"]) if s["time"] else datetime.max)

    stages.sort(key=_order_key)
    for i, stage in enumerate(stages, start=1):
        stage["order"] = i

    return {
        "stages": stages,
        "overall_confidence": _overall_confidence(stages),
        "stage_count": len(stages),
    }
