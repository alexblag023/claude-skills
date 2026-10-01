#!/usr/bin/env python3
"""Поиск утечек ресурсов в Java (CWE-404/CWE-772): Connection, Statement, PreparedStatement, ResultSet, потоки, Reader/Writer, Socket.

Почему скрипт, а не правило Semgrep: «закрыт ли ресурс где-либо в методе» (в finally любой вложенности, в try-with-resources,
через обёртку) шаблонами Semgrep описывается плохо; здесь проверка детерминирована и тестируется.

Алгоритм (на каждый метод, без запуска кода):
  1. Комментарии и строки вычищаются (номера строк сохраняются).
  2. В теле метода ищутся присваивания `X = <открытие ресурса>` (createStatement/prepareStatement/prepareCall/executeQuery/
     getConnection, new FileInputStream/FileReader/BufferedReader/Scanner/Socket/..., Files.newBufferedReader/lines/list/walk).
  3. Ресурс считается безопасным, если: объявлен в `try (...)`; в методе есть `X.close()` / `closeQuietly(X)` / `close(X)`;
     он возвращается или присваивается полю/другой переменной (владение передано); передан в конструктор обёртки
     (закрытие обёртки закроет и его); он порождён от родителя (`X = P.method(...)`), который закрывается (закрытие
     Connection закрывает Statement, Statement — ResultSet).
  4. Иначе — находка: file:line открытия.

Пределы (эвристика): ресурсы, закрываемые в ДРУГОМ методе, и сложное владение (коллекции, поля, фабрики) помечаются как
утечка или пропускаются — проверяйте вручную. Spring JdbcTemplate/try-with-resources в Lombok `@Cleanup` не разбираются.

Использование: python java_resource_leak_lint.py <файл|каталог> [--json | --sarif] [--strict]
Код возврата: 0 — утечек нет, 1 — есть находки.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

STRICT = False  # --strict: закрытие родителя не освобождает дочерние Statement/ResultSet
SKIP_DIRS = {'.git', 'node_modules', 'target', 'build', 'out', '.idea', '__pycache__'}

ACQ_CALL = re.compile(r'\.\s*(createStatement|prepareStatement|prepareCall|executeQuery|getConnection)\s*\(')
ACQ_NEW = re.compile(r'\bnew\s+(?:java\.\w+\.)*(FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|'
                     r'BufferedWriter|InputStreamReader|OutputStreamWriter|PrintWriter|PrintStream|Scanner|Socket|'
                     r'ServerSocket|ZipFile|RandomAccessFile|ObjectInputStream|ObjectOutputStream|DataInputStream|'
                     r'DataOutputStream|BufferedInputStream|BufferedOutputStream)\s*\(')
ACQ_FILES = re.compile(r'\bFiles\s*\.\s*(newBufferedReader|newBufferedWriter|newInputStream|newOutputStream|lines|list|walk|find|'
                       r'newDirectoryStream)\s*\(')
ASSIGN = re.compile(r'^\s*(?:final\s+)?(?:[\w.]+(?:<[^=;]*?>)?(?:\[\s*\])*\s+)?(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+)$', re.S)
CTRL = {'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'try', 'else', 'return', 'new', 'do', 'throw', 'assert'}
HEADER = re.compile(r'\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}()]*(?:\([^)]*\)[^;{}()]*)*)\)\s*'
                    r'(?:throws\s+[\w.,\s]+)?\s*\{')


def strip_noise(src: str) -> str:
    """Заменяет комментарии и содержимое строк/символов пробелами, сохраняя переводы строк и длину."""
    out, i, n = [], 0, len(src)
    while i < n:
        c, two = src[i], src[i:i + 2]
        if two == '//':
            j = src.find('\n', i)
            j = n if j == -1 else j
            out.append(' ' * (j - i)); i = j
        elif two == '/*':
            j = src.find('*/', i + 2)
            j = n if j == -1 else j + 2
            out.append(''.join('\n' if ch == '\n' else ' ' for ch in src[i:j])); i = j
        elif c in '"\'':
            if src[i:i + 3] == '"""':
                j = src.find('"""', i + 3)
                j = n if j == -1 else j + 3
                out.append(''.join('\n' if ch == '\n' else ' ' for ch in src[i:j])); i = j
                continue
            j = i + 1
            while j < n and src[j] != c and src[j] != '\n':
                j += 2 if src[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(c + ' ' * max(j - i - 2, 0) + (c if j - i >= 2 else '')); i = j
        else:
            out.append(c); i += 1
    return ''.join(out)


def match_brace(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == '{':
            depth += 1
        elif s[k] == '}':
            depth -= 1
            if depth == 0:
                return k
    return len(s) - 1


def split_statements(body: str, base: int):
    """Грубое разбиение тела на «операторы» по `;` с глубиной скобок; даёт (смещение_начала, текст)."""
    # глубина считается только по () и []: `;` и границы блоков `{`/`}` (try {, } catch (...) {, finally {)
    # заканчивают оператор на любой вложенности блоков, но не внутри круглых скобок (аргументы, лямбды, инициализаторы)
    paren, start = 0, 0
    for i, ch in enumerate(body):
        if ch in '([':
            paren += 1
        elif ch in ')]':
            paren -= 1
        elif paren <= 0 and ch in ';{}':
            yield base + start, body[start:i]
            start = i + 1


def find_methods(clean: str):
    for m in HEADER.finditer(clean):
        if m.group('name') in CTRL:
            continue
        # заголовок метода: перед именем модификаторы/тип; исключаем вызовы вида `foo(...) {` внутри выражений-лямбд
        before = clean[max(0, m.start() - 80):m.start()]
        if re.search(r'(=|->|\(|,)\s*$', before):
            continue
        open_idx = m.end() - 1
        yield m.group('name'), open_idx, match_brace(clean, open_idx)


def analyze_method(clean: str, open_idx: int, close_idx: int):
    body = clean[open_idx + 1:close_idx]
    base = open_idx + 1
    twr = set()  # переменные из try(...)
    for t in re.finditer(r'\btry\s*\(', body):
        depth, k = 0, t.end() - 1
        for k in range(t.end() - 1, len(body)):
            depth += body[k] == '('
            depth -= body[k] == ')'
            if depth == 0:
                break
        for v in re.finditer(r'(?:^|;|\()\s*(?:final\s+)?[\w.<>\[\]?,\s]*?\b(\w+)\s*=', body[t.end():k]):
            twr.add(v.group(1))
        twr.update(re.findall(r'^\s*(\w+)\s*$', body[t.end():k], re.M))  # try (existingVar)
    acquired = {}  # var -> (offset, kind, parent)
    for off, st in split_statements(body, base):
        a = ASSIGN.match(st)
        if not a:
            continue
        rhs, var = a.group('rhs'), a.group('var')
        if not (ACQ_CALL.search(rhs) or ACQ_NEW.search(rhs) or ACQ_FILES.search(rhs)):
            continue
        if var in twr or var in acquired:
            continue
        pm = re.match(r'\s*(?:\(\s*[\w.<>]+\s*\)\s*)?(?P<p>[A-Za-z_]\w*)\s*\.\s*\w+\s*\(', rhs)
        parent = pm.group('p') if pm else None
        kind = (ACQ_CALL.search(rhs) or ACQ_NEW.search(rhs) or ACQ_FILES.search(rhs)).group(1)
        acquired[var] = (off + (len(st) - len(st.lstrip())), kind, parent)

    def closed(v: str, seen=()) -> bool:
        if re.search(rf'\b{re.escape(v)}\s*\.\s*close\s*\(', body):
            return True
        if re.search(rf'\bclose\w*\s*\([^)]*\b{re.escape(v)}\b', body):          # closeQuietly(v), IOUtils.close(v), DbUtils.close(v)
            return True
        # владение передано вызывающему: `return v;`, `return (T) v;` или `return new Обёртка(... v ...)`.
        # `return v.read()` — возвращено значение, а не ресурс: утечка остаётся.
        if re.search(rf'\breturn\s+(?:\(\s*[\w.<>]+\s*\)\s*)?{re.escape(v)}\s*;', body) or \
                re.search(rf'\breturn\s+new\s+[\w.<>]+\s*\([^;]*?(?<![\w.]){re.escape(v)}\s*(?=[,)])', body):
            return True
        if re.search(rf'\bthis\s*\.\s*\w+\s*=\s*{re.escape(v)}\b', body):             # сохранён в поле
            return True
        if re.search(rf'(?<![\w.])[A-Za-z_]\w*\s*=\s*{re.escape(v)}\s*;', body):        # псевдоним
            return True
        # передан обёртке ЦЕЛЫМ аргументом: new W(v), new W(a, v). `new User(v.getString(..))` — это чтение значения
        if re.search(rf'\bnew\s+[\w.]+\s*\([^;]*?(?<![\w.]){re.escape(v)}\s*(?=[,)])', body):
            return True
        parent = acquired.get(v, (0, '', None))[2]
        # по спецификации JDBC закрытие Connection/Statement закрывает дочерние Statement/ResultSet; в строгом режиме
        # (--strict, как требуют многие сканеры) каждый объект должен закрываться явно
        if not STRICT and parent and parent in acquired and parent not in seen:
            return closed(parent, seen + (v,))
        return False

    return [(off, v, kind) for v, (off, kind, parent) in acquired.items() if not closed(v)]


def lint_file(path: Path):
    try:
        src = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    clean = strip_noise(src)
    seen_lines, out = set(), []
    methods = list(find_methods(clean))
    # внутренние методы раньше внешних: находка принадлежит самому внутреннему
    for name, o, c in sorted(methods, key=lambda x: x[2] - x[1]):
        for off, var, kind in analyze_method(clean, o, c):
            line = clean.count('\n', 0, off) + 1
            if line in seen_lines:
                continue
            seen_lines.add(line)
            out.append({'file': str(path), 'line': line, 'method': name, 'variable': var, 'resource': kind,
                        'cwe': 'CWE-404',
                        'issue': f'ресурс «{var}» ({kind}) открыт в методе {name}(), но не закрывается '
                                 f'(нет close()/try-with-resources/передачи владения)'})
    return sorted(out, key=lambda x: x['line'])


def scan(root: Path):
    files = [root] if root.is_file() else (p for p in root.rglob('*.java') if not SKIP_DIRS & set(p.parts))
    res = []
    for f in files:
        res += lint_file(f)
    return res


def to_sarif(findings):
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'java_resource_leak_lint', 'rules': [{
            'id': 'java-resource-leak', 'name': 'ResourceLeak',
            'shortDescription': {'text': 'Improper Resource Shutdown or Release (CWE-404)'},
            'properties': {'tags': ['CWE-404'], 'security-severity': '4.0'}}]}},
        'results': [{'ruleId': 'java-resource-leak', 'level': 'warning', 'message': {'text': f['issue']},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': f['file']},
                                                         'region': {'startLine': f['line']}}}]} for f in findings]}]}


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if not args:
        print(__doc__)
        sys.exit(2)
    STRICT = '--strict' in sys.argv
    found = scan(Path(args[0]))
    if '--sarif' in sys.argv:
        print(json.dumps(to_sarif(found), ensure_ascii=False, indent=1))
    elif '--json' in sys.argv:
        print(json.dumps(found, ensure_ascii=False, indent=1))
    else:
        for f in found:
            print(f"{f['file']}:{f['line']}: CWE-404 {f['issue']}")
        print(f'java_resource_leak_lint: {len(found)} находок')
    sys.exit(1 if found else 0)
