#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

DEFAULT_MAPPING = Path(__file__).resolve().parent / 'doc' / 'mapping.md'

KEYWORDS = {
    'if', 'else', 'for', 'while', 'switch', 'case', 'return',
    'sizeof', 'do', 'goto', 'break', 'continue', 'typedef',
    'struct', 'enum', 'union', 'static', 'extern', 'const',
    'volatile', 'signed', 'unsigned', 'void', 'char', 'int',
    'long', 'short', 'float', 'double', 'register', 'auto',
    'inline', 'restrict', 'NULL', 'true', 'false'
}


def extract_pattern_block(mapping_text: str):
    section = mapping_text.split('## 패턴 정리', 1)
    if len(section) != 2:
        raise ValueError('mapping.md에서 "## 패턴 정리" 섹션을 찾을 수 없습니다.')

    lines = section[1].splitlines()
    patterns = []
    current = None

    for raw_line in lines:
        line = raw_line.rstrip()
        m = re.match(r'^\s*(\d+)\.\s*(.+)$', line)
        if m:
            if current:
                patterns.append(current)
            current = {'name': m.group(2).strip(), 'legacy': None, 'pqc': None}
            continue

        if current is None:
            continue

        if re.match(r'^\s*-\s*Legacy\s*:', line):
            current['legacy'] = {'flow': line.split(':', 1)[1].strip(), 'pre': '', 'post': ''}
            continue

        if re.match(r'^\s*-\s*PQC\s*:', line):
            current['pqc'] = {'flow': line.split(':', 1)[1].strip(), 'pre': '', 'post': ''}
            continue

        if re.match(r'^\s*\*\s*선행 조건\s*:', line):
            if current['legacy'] and current['legacy'].get('pre', '') == '' and current['legacy'].get('flow') is not None:
                current['legacy']['pre'] = line.split(':', 1)[1].strip()
            elif current['pqc'] and current['pqc'].get('pre', '') == '' and current['pqc'].get('flow') is not None:
                current['pqc']['pre'] = line.split(':', 1)[1].strip()
            continue

        if re.match(r'^\s*\*\s*후행 조건\s*:', line):
            if current['legacy'] and current['legacy'].get('post', '') == '' and current['legacy'].get('flow') is not None:
                current['legacy']['post'] = line.split(':', 1)[1].strip()
            elif current['pqc'] and current['pqc'].get('post', '') == '' and current['pqc'].get('flow') is not None:
                current['pqc']['post'] = line.split(':', 1)[1].strip()
            continue

    if current:
        patterns.append(current)

    return patterns


def parse_flow_function_names(flow: str):
    if not flow:
        return []
    tokens = re.split(r'\s*(?:->|→)\s*', flow)
    funcs = []
    for token in tokens:
        m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', token)
        if m:
            name = m.group(1)
            if name not in KEYWORDS:
                funcs.append(name)
    return funcs


def parse_condition_vars(cond_text: str):
    if not cond_text:
        return []
    vars = []
    for token in re.split(r'[,;]', cond_text):
        token = token.strip()
        if not token:
            continue
        m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\[', token)
        if m:
            vars.append(m.group(1))
            continue
        m = re.search(r'\*\s*([A-Za-z_][A-Za-z0-9_]*)\b', token)
        if m:
            vars.append(m.group(1))
            continue
        m = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*)\b$', token)
        if m:
            name = m.group(1)
            if name not in KEYWORDS:
                vars.append(name)
    return vars


def extract_function_calls(c_file: Path):
    text = c_file.read_text(encoding='utf-8', errors='ignore')
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//.*', '', text)
    matches = re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', text)
    calls = []
    for m in matches:
        name = m.group(1)
        if name in KEYWORDS:
            continue
        calls.append(name)
    return calls


def contains_flow(calls, flow_names):
    if not flow_names:
        return False
    if len(calls) < len(flow_names):
        return False

    pattern_index = 0
    for call in calls:
        if call == flow_names[pattern_index]:
            pattern_index += 1
            if pattern_index == len(flow_names):
                return True
    return False


def build_pattern_index(mapping_path: Path):
    mapping_text = mapping_path.read_text(encoding='utf-8', errors='ignore')
    patterns = extract_pattern_block(mapping_text)
    index = []
    for pat in patterns:
        for kind, label in [('legacy', 'Legacy'), ('pqc', 'PQC')]:
            item = pat.get(kind)
            if not item:
                continue
            flow_names = parse_flow_function_names(item['flow'])
            pre_vars = parse_condition_vars(item.get('pre', ''))
            post_vars = parse_condition_vars(item.get('post', ''))
            index.append({
                'pattern_name': pat['name'],
                'kind': label,
                'version': 'OpenSSL 1.0.8u' if kind == 'legacy' else 'OpenSSL 3.5.8',
                'flow': item['flow'],
                'flow_names': flow_names,
                'pre_vars': pre_vars,
                'post_vars': post_vars,
            })
    return index


def find_matching_patterns(c_file: Path, mapping_path: Path):
    calls = extract_function_calls(c_file)
    matches = []
    for entry in build_pattern_index(mapping_path):
        if contains_flow(calls, entry['flow_names']):
            matches.append(entry)
    return matches


def main():
    parser = argparse.ArgumentParser(description='Read mapping.md patterns and match against a C source file.')
    parser.add_argument('c_file', help='C source file to analyze')
    parser.add_argument('--mapping', default=str(DEFAULT_MAPPING), help='Path to mapping.md (default: pqc/doc/mapping.md)')
    args = parser.parse_args()

    c_path = Path(args.c_file).resolve()
    mapping_path = Path(args.mapping).resolve()

    if not c_path.exists():
        raise FileNotFoundError(f'C file not found: {c_path}')
    if not mapping_path.exists():
        raise FileNotFoundError(f'mapping.md not found: {mapping_path}')

    matches = find_matching_patterns(c_path, mapping_path)
    if not matches:
        print(f'No pattern match for {c_path}')
        return 0

    for item in matches:
        print(f"Pattern: {item['pattern_name']} | {item['kind']} | {item['version']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
