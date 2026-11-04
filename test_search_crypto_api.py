#!/usr/bin/env python3
from pathlib import Path

from SearchCryptoAPI import find_matching_patterns

ROOT = Path(__file__).resolve().parent
MAPPING = ROOT / 'doc' / 'mapping.md'

EXPECTED_BY_FILE = {
    'ch2/mkrand16.c': {'난수/시드 생성'},
    'ch2/rsagenkey.c': {'키 생성'},
    'ch2/pqc/pqc_mkrand16.c': {'난수/시드 생성'},
    'ch2/pqc/pqc_mldsa_genkey.c': {'키 생성'},

    'ch3/aes_128_cbc.c': {'EVP기반 CBC 암호', 'EVP기반 CBC 복호'},
    'ch3/pqc/pqc_aes_256_cbc.c': {'EVP기반 CBC 암호', 'EVP기반 CBC 복호'},

    'ch4/rsatest.c': {'키 생성', 'RSA OAEP기반 암호', 'RSA OAEP 기반 복호'},
    'ch4/rsa_des_crc.c': {'EVP기반 CBC 암호', 'EVP기반 CBC 복호', 'RSA OAEP기반 암호', 'RSA OAEP 기반 복호'},
    'ch4/pqc/pqc_mlkem_envelope.c': {'RSA OAEP기반 암호', 'RSA OAEP 기반 복호'},
    'ch4/pqc/pqc_mlkem_file.c': {'RSA OAEP기반 암호', 'RSA OAEP 기반 복호'},

    'ch5/rsa_sha1_sign_test.c': {'서명', '검증'},
    'ch5/pqc/pqc_mldsa_sign_test.c': {'서명', '검증'},

    'ch7/hash_sign.c': {'서명', '검증'},
    'ch7/pqc/pqc_hash_sign.c': {'서명', '검증'},

    'ch8/client0.c': {'SYMMKEY 암호'},
    'ch8/server0.c': {'SYMMKEY 복호'},
    'ch8/pqc/pqc_client0.c': {'SYMMKEY 암호'},
    'ch8/pqc/pqc_server0.c': {'SYMMKEY 복호'},

    'ch9/ssl_client.c': {'TLS Client config'},
    'ch9/ssl_server.c': {'TLS Server config'},
    'ch9/pqc/pqc_ssl_client.c': {'TLS Client config'},
    'ch9/pqc/pqc_ssl_server.c': {'TLS Server config'},
}


def normalize_results(matches):
    return {item['pattern_name'] for item in matches}


def classify(file_rel: str):
    abs_path = (ROOT / file_rel).resolve()
    matches = find_matching_patterns(abs_path, MAPPING)
    matched = normalize_results(matches)
    expected = EXPECTED_BY_FILE[file_rel]
    missing = expected - matched
    extra = matched - expected

    if not missing and not extra:
        status = 'PASS'
    elif matched & expected and extra:
        status = 'FALSE_POSITIVE'
    else:
        status = 'FAIL'

    return {
        'file': file_rel,
        'status': status,
        'expected': expected,
        'matched': matched,
        'missing': missing,
        'extra': extra,
    }


def numbered_pattern_names():
    names = sorted({
        pattern_name
        for pattern_set in EXPECTED_BY_FILE.values()
        for pattern_name in pattern_set
    })
    return {name: idx + 1 for idx, name in enumerate(names)}


PATTERN_INDEX = numbered_pattern_names()


def code_list(values):
    return ', '.join(str(PATTERN_INDEX[v]) for v in sorted(values))


def main():
    files = sorted(EXPECTED_BY_FILE)
    results = [classify(path) for path in files]

    passed = sum(1 for r in results if r['status'] == 'PASS')
    false_positive = sum(1 for r in results if r['status'] == 'FALSE_POSITIVE')
    failed = sum(1 for r in results if r['status'] == 'FAIL')

    total = len(results)
    pass_rate = (passed / total * 100) if total else 0.0
    fp_rate = (false_positive / total * 100) if total else 0.0

    print('Pattern index:')
    for name, idx in sorted(PATTERN_INDEX.items(), key=lambda kv: kv[1]):
        print(f'  {idx}. {name}')
    print('-' * 80)
    print('SearchCryptoAPI.py test summary')
    print('-' * 80)
    for idx, r in enumerate(results, 1):
        expected = code_list(r['expected'])
        matched = code_list(r['matched'])
        extra = code_list(r['extra'])
        missing = code_list(r['missing'])

        if r['status'] == 'PASS':
            print(f"{idx}. PASS    {r['file']} | expected=[{expected}] | matched=[{matched}]")
        elif r['status'] == 'FALSE_POSITIVE':
            print(f"{idx}. FP      {r['file']} | expected=[{expected}] | matched=[{matched}] | extra=[{extra}]")
        else:
            print(f"{idx}. FAIL    {r['file']} | expected=[{expected}] | matched=[{matched}] | missing=[{missing}] | extra=[{extra}]")

    print('-' * 80)
    print(f'Total files tested: {total}')
    print(f'Passed: {passed}')
    print(f'False Positive: {false_positive}')
    print(f'Failed: {failed}')
    print(f'Pass rate: {pass_rate:.2f}%')
    print(f'False Positive rate: {fp_rate:.2f}%')


if __name__ == '__main__':
    main()
