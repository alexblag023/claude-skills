#!/usr/bin/env python3
"""Нормализация выгрузок внешних сканеров в единый список находок + гейт по High/Critical.

Поддерживаемые форматы (автоопределение, либо --format):
  sarif        SARIF 2.1.0: Snyk (`snyk code test --sarif`), Checkmarx One (`cx ... --report-format sarif`),
               CodeQL/GHAS, Semgrep, Trivy, и любой другой SARIF-совместимый сканер
  ghas         GitHub code scanning REST: ответ `GET /repos/{o}/{r}/code-scanning/alerts` (список алертов)
  sonar        SonarQube `api/issues/search` ({"issues":[...]}) и `api/hotspots/search` ({"hotspots":[...]})
  veracode     Veracode Pipeline Scan results.json ({"findings":[...]})
  kics         KICS (Checkmarx) родной JSON (`kics scan --report-formats json`) — IaC: Terraform/K8s/Docker/…
  checkmarx    Checkmarx One JSON (`--report-format json`: {"results":[...]})
  cxsast       CxSAST XML (<CxXMLResults>)
  fortify      Fortify `FPRUtility -information -listIssues ... -outputFormat CSV` (поиск колонок по имени, best-effort)
  appscreener  Solar appScreener `Detailed_Results.csv`

Только стандартная библиотека. Имена полей взяты из официальной документации и открытых клиентов; НЕ все
подтверждены живой выгрузкой (см. references/external_tools_cookbook.md) — нераспознанные поля не роняют скрипт,
находка получает severity Info/пустые поля, а в сводку выводится предупреждение.

Использование:
  python ingest_external_report.py <файл> [<файл> ...] [--format X] [--fail-on high|critical|medium] [--json]
Код возврата: 0 — блокеров нет, 1 — есть открытые находки не ниже порога, 2 — ошибка чтения/формата.
"""
from __future__ import annotations

import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LEVELS = ['Info', 'Low', 'Medium', 'High', 'Critical']
CSRF_RE = re.compile(r'csrf|xsrf|cross.?site.?request|подделк\w*\s+запрос', re.I)
SECRET_TOOLS = {'gitleaks', 'trufflehog', 'detect-secrets', 'ggshield'}
SUPPRESSED_STATES = {
    'suppressed', 'dismissed', 'fixed', 'closed', 'resolved', 'false_positive', 'false-positive', 'falsepositive', 'accepted',
    'safe', 'reviewed', 'not_exploitable', 'proposed_not_exploitable', 'wont_fix', 'mitigated',
    'отклонено', 'отклонена', 'исправлено',
}


def norm_severity(raw) -> str:
    """Приводит шкалы разных сканеров к Info/Low/Medium/High/Critical."""
    if raw is None or raw == '':
        return 'Info'
    if isinstance(raw, (int, float)) or re.fullmatch(r'\d+(\.\d+)?', str(raw).strip()):
        n = float(raw)
        if n <= 5 and float(n).is_integer():           # Veracode 0..5
            return ['Info', 'Low', 'Low', 'Medium', 'High', 'Critical'][int(n)]
        return 'Critical' if n >= 9 else 'High' if n >= 7 else 'Medium' if n >= 4 else 'Low' if n > 0 else 'Info'
    s = str(raw).strip().lower().replace('_', ' ')
    table = {
        'critical': 'Critical', 'blocker': 'Critical', 'very high': 'Critical', 'критический': 'Critical',
        'critical high': 'Critical',
        'high': 'High', 'error': 'High', 'major high': 'High', 'высокий': 'High',
        'medium': 'Medium', 'warning': 'Medium', 'moderate': 'Medium', 'средний': 'Medium',
        'low': 'Low', 'note': 'Low', 'minor': 'Low', 'very low': 'Low', 'низкий': 'Low',
        'info': 'Info', 'informational': 'Info', 'none': 'Info', 'информационный': 'Info',
    }
    if s in table:
        return table[s]
    return {'major': 'Medium', 'critical': 'Critical'}.get(s, 'Info')


def finding(tool, rule='', title='', severity='Info', file='', line=0, cwe='', state='open', raw_sev=''):
    suppressed = str(state or '').strip().lower().replace(' ', '_') in SUPPRESSED_STATES
    return {'tool': tool, 'rule': str(rule or ''), 'title': str(title or ''), 'severity': severity,
            'file': str(file or ''), 'line': int(line or 0), 'cwe': str(cwe or ''), 'state': str(state or 'open'),
            'suppressed': suppressed, 'raw_severity': str(raw_sev),
            'csrf': bool(CSRF_RE.search(f'{rule} {title}') or re.search(r'(?<!\d)352(?!\d)', str(cwe)))}


def _int(v) -> int:
    try:
        return int(str(v).split('-')[0])
    except (TypeError, ValueError):
        return 0


def _cwe_from(items) -> str:
    for t in items or []:
        m = re.search(r'cwe[-_/ ]*(\d+)', str(t), re.I)
        if m:
            return f'CWE-{m.group(1)}'
    return ''


# ---------------- парсеры ----------------
def parse_sarif(doc, tool_label=None):
    out = []
    for run in doc.get('runs', []):
        driver = (run.get('tool') or {}).get('driver') or {}
        tool = tool_label or driver.get('name') or 'sarif'
        rules = {r.get('id'): r for r in driver.get('rules', []) if isinstance(r, dict)}
        for res in run.get('results', []):
            rid = res.get('ruleId') or ''
            rule = rules.get(rid)
            idx = res.get('ruleIndex')
            if rule is None and isinstance(idx, int) and 0 <= idx < len(driver.get('rules') or []):
                rule = driver['rules'][idx]  # SARIF допускает ссылку на правило по индексу
            rule = rule or {}
            props = {**(rule.get('properties') or {}), **(res.get('properties') or {})}
            # числовая оценка: security-severity (CodeQL/GHAS) или riskScore (KICS — реальный вывод, level там нет)
            sec = props.get('security-severity') or props.get('riskScore')
            # SARIF 2.1.0: отсутствующий level = warning (так и выдаёт, например, gitleaks)
            level = res.get('level') or (rule.get('defaultConfiguration') or {}).get('level') or 'warning'
            sev = norm_severity(sec) if sec not in (None, '') else norm_severity(level)
            if tool.lower() in SECRET_TOOLS and LEVELS.index(sev) < LEVELS.index('High'):
                sev = 'High'  # утечка секрета — минимум High (verified secret = инцидент, не гигиена)
            loc = ((res.get('locations') or [{}])[0].get('physicalLocation') or {})
            file = (loc.get('artifactLocation') or {}).get('uri', '')
            line = (loc.get('region') or {}).get('startLine', 0)
            supp = 'suppressed' if res.get('suppressions') else 'open'
            out.append(finding(tool, rid, (res.get('message') or {}).get('text', '') or rule.get('name', ''),
                               sev, file, line, _cwe_from(props.get('tags') or props.get('cwe')), supp,
                               sec if sec else level))
    return out


def parse_ghas(doc):
    out = []
    for a in doc if isinstance(doc, list) else []:
        rule = a.get('rule') or {}
        inst = (a.get('most_recent_instance') or {}).get('location') or {}
        sev = norm_severity(rule.get('security_severity_level') or rule.get('severity'))
        out.append(finding(f"GHAS/{(a.get('tool') or {}).get('name', 'code-scanning')}", rule.get('id'),
                           rule.get('description') or rule.get('name'), sev, inst.get('path'), inst.get('start_line'),
                           _cwe_from(rule.get('tags')), a.get('state', 'open'),
                           rule.get('security_severity_level') or rule.get('severity')))
    return out


def parse_sonar(doc):
    out = []
    for i in doc.get('issues', []):
        impacts = [x.get('severity') for x in i.get('impacts', []) if isinstance(x, dict)]
        raw = max(impacts, key=lambda s: LEVELS.index(norm_severity(s))) if impacts else i.get('severity')
        out.append(finding('SonarQube', i.get('rule'), i.get('message'), norm_severity(raw),
                           (i.get('component') or '').split(':', 1)[-1], i.get('line') or (i.get('textRange') or {}).get('startLine'),
                           _cwe_from(i.get('tags')), i.get('issueStatus') or i.get('status') or i.get('resolution') or 'open',
                           raw))
    for h in doc.get('hotspots', []):
        raw = h.get('vulnerabilityProbability')
        state = h.get('resolution') if h.get('status') == 'REVIEWED' else 'open'
        out.append(finding('SonarQube/hotspot', h.get('ruleKey'), h.get('message'), norm_severity(raw),
                           (h.get('component') or '').split(':', 1)[-1], h.get('line'), '', state or 'reviewed', raw))
    return out


def parse_veracode(doc):
    # Схема подтверждена исходниками конвертера Veracode (veracode-pipeline-scan-results-to-sarif):
    # верхний уровень scan_status/findings[]; при неуспешном скане findings пуст — это НЕ «чисто».
    status = doc.get('scan_status')
    if status not in (None, 'SUCCESS'):
        raise ValueError(f'Veracode scan_status={status!r}: скан не завершён успешно, результаты неполные '
                         f'({doc.get("message", "")}) — пустой список находок не означает «чисто»')
    out = []
    for f in doc.get('findings', []):
        files = f.get('files') or {}
        src = files.get('source_file') or {} if isinstance(files, dict) else {}
        out.append(finding('Veracode', f.get('issue_type') or f.get('issue_id'), f.get('title'),
                           norm_severity(f.get('severity')), src.get('file') or f.get('file'),
                           src.get('line') or f.get('line'), f'CWE-{f["cwe_id"]}' if f.get('cwe_id') else '',
                           f.get('finding_status', {}).get('resolution_status') if isinstance(f.get('finding_status'), dict) else 'open',
                           f.get('severity')))
    return out


def parse_checkmarx(doc):
    out = []
    for r in doc.get('results', []):
        d = r.get('data') or {}
        vd = r.get('vulnerabilityDetails') or {}
        out.append(finding('Checkmarx One', d.get('queryName') or r.get('id'), d.get('queryName') or r.get('description'),
                           norm_severity(r.get('severity')), d.get('fileName'), d.get('line'),
                           f'CWE-{vd["cweId"]}' if vd.get('cweId') else '', r.get('state') or r.get('status') or 'open',
                           r.get('severity')))
    return out


def parse_kics(doc):
    """Родной JSON KICS (`--report-formats json`): queries[] {query_name, severity, cwe, risk_score, files[]}."""
    if doc.get('files_scanned') == 0:
        raise ValueError('KICS: files_scanned=0 — ни один файл не просканирован, пустой результат не означает «чисто»')
    out = []
    for q in doc.get('queries', []):
        for f in q.get('files') or [{}]:
            out.append(finding('KICS', q.get('query_name'), q.get('query_name'), norm_severity(q.get('severity')),
                               f.get('file_name'), f.get('line'), f'CWE-{q["cwe"]}' if q.get('cwe') else '',
                               'open', q.get('severity')))
    return out


def parse_cxsast(root):
    out = []
    for q in root.iter('Query'):
        for res in q.iter('Result'):
            state = 'false_positive' if str(res.get('FalsePositive', '')).lower() == 'true' else (res.get('Status') or 'open')
            sev = res.get('Severity') or q.get('Severity')
            out.append(finding('CxSAST', q.get('name'), q.get('name'), norm_severity(sev), res.get('FileName'),
                               res.get('Line'), f'CWE-{q.get("cweId")}' if q.get('cweId') else '', state, sev))
    return out


def _col(row_keys, *needles):
    for k in row_keys:
        kl = k.lower()
        if any(n in kl for n in needles):
            return k
    return None


def parse_fortify_csv(rows):
    out = []
    if not rows:
        return out
    keys = list(rows[0].keys())
    c_cat, c_sev = _col(keys, 'category', 'issue name', 'vulnerability'), _col(keys, 'friority', 'priority', 'severity')
    c_file, c_line = _col(keys, 'path', 'file'), _col(keys, 'line')
    for r in rows:
        file = r.get(c_file, '') if c_file else ''
        line = r.get(c_line, 0) if c_line else 0
        if ':' in str(file) and not line:
            file, _, line = str(file).rpartition(':')
        out.append(finding('Fortify', r.get(c_cat, ''), r.get(c_cat, ''), norm_severity(r.get(c_sev) if c_sev else ''),
                           file, line, '', 'open', r.get(c_sev, '') if c_sev else ''))
    return out


def parse_appscreener_csv(rows):
    return [finding('Solar appScreener', r.get('Vulnerability'), r.get('Vulnerability'),
                    norm_severity(r.get('Severity Level')), r.get('File'), r.get('Line'), '', 'open',
                    r.get('Severity Level')) for r in rows]


# ---------------- загрузка и автоопределение ----------------
def load(path: Path, fmt: str | None):
    text = path.read_text(encoding='utf-8-sig', errors='replace')
    head = text.lstrip()[:1]
    if fmt is None:
        if head in '[{':
            fmt = 'json'
        elif head == '<':
            fmt = 'xml'
        else:
            fmt = 'csv'
    if fmt in ('sarif', 'ghas', 'sonar', 'veracode', 'checkmarx', 'kics', 'json'):
        doc = json.loads(text)
        if fmt == 'json':
            if isinstance(doc, dict) and 'runs' in doc:
                fmt = 'sarif'
            elif isinstance(doc, list):
                fmt = 'ghas'
            elif 'kics_version' in doc and 'queries' in doc:
                fmt = 'kics'
            elif 'issues' in doc or 'hotspots' in doc:
                fmt = 'sonar'
            elif 'findings' in doc:
                fmt = 'veracode'
            elif 'results' in doc:
                fmt = 'checkmarx'
            else:
                raise ValueError('неизвестная структура JSON; укажите --format')
        return {'sarif': parse_sarif, 'ghas': parse_ghas, 'sonar': parse_sonar,
                'veracode': parse_veracode, 'checkmarx': parse_checkmarx, 'kics': parse_kics}[fmt](doc), fmt
    if fmt in ('cxsast', 'xml'):
        if re.search(r'<!DOCTYPE|<!ENTITY', text, re.I):  # недоверенный XML: без DTD/сущностей (XXE, billion laughs)
            raise ValueError('XML содержит DOCTYPE/ENTITY — отклонён')
        return parse_cxsast(ET.fromstring(text)), 'cxsast'
    if fmt in ('fortify', 'appscreener', 'csv'):
        rows = list(csv.DictReader(text.splitlines(), delimiter=';' if text.split('\n', 1)[0].count(';') > text.split('\n', 1)[0].count(',') else ','))
        keys = set(rows[0].keys()) if rows else set()
        if fmt == 'csv':
            fmt = 'appscreener' if {'Vulnerability', 'Severity Level'} <= keys else 'fortify'
        return (parse_appscreener_csv(rows) if fmt == 'appscreener' else parse_fortify_csv(rows)), fmt
    raise ValueError(f'неизвестный формат {fmt}')


def main(argv: list[str]) -> int:
    files = [a for a in argv if not a.startswith('--') and Path(a).exists()]
    opt = lambda name, default=None: argv[argv.index(name) + 1] if name in argv else default  # noqa: E731
    fmt, fail_on = opt('--format'), (opt('--fail-on', 'high') or 'high').capitalize()
    if not files or fail_on not in LEVELS:
        print(__doc__)
        return 2
    all_f, warnings = [], []
    for f in files:
        try:
            items, used = load(Path(f), fmt)
        except Exception as e:  # noqa: BLE001 — формат внешний, ошибку показываем пользователю
            print(f'ОШИБКА {f}: {e}')
            return 2
        if items and all(i['severity'] == 'Info' and i['raw_severity'] not in ('', 'None') for i in items):
            warnings.append(f'{f}: у всех находок severity распознан как Info при непустом исходном значении — '
                            f'проверьте шкалу формата «{used}»')
        all_f += items
    open_f = [i for i in all_f if not i['suppressed']]
    thr = LEVELS.index(fail_on)
    blockers = [i for i in open_f if LEVELS.index(i['severity']) >= thr]
    csrf = [i for i in open_f if i['csrf']]
    if '--json' in argv:
        print(json.dumps({'findings': all_f, 'blockers': len(blockers), 'csrf_class': len(csrf)}, ensure_ascii=False, indent=1))
    else:
        for i in sorted(blockers, key=lambda x: -LEVELS.index(x['severity'])):
            print(f"[{i['severity']}] {i['tool']}: {i['rule'] or i['title']} — {i['file']}:{i['line']} {i['cwe']}")
        by = {}
        for i in all_f:
            by[i['severity']] = by.get(i['severity'], 0) + 1
        print(f"Всего находок: {len(all_f)} (открытых {len(open_f)}), по severity: "
              f"{', '.join(f'{k}={by[k]}' for k in reversed(LEVELS) if k in by) or '-'}")
        print(f'Блокеров (открытые, не ниже {fail_on}): {len(blockers)}')
        if csrf:
            print(f'Класс CSRF: {len(csrf)} открытых — прогоните scripts/csrf_template_lint.py и добавьте токен в разметку.')
        for w in warnings:
            print('ПРЕДУПРЕЖДЕНИЕ', w)
    return 1 if blockers else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main(sys.argv[1:]))
