"""Tests for ErrSight error path security auditor."""
from errsight import scan_source
from main import main


def test_password_leaked_in_log():
    code = (
        'try:\n'
        '    authenticate(user, password)\n'
        'except Exception as e:\n'
        '    logging.error(f"Auth failed: {password}")\n'
    )
    findings = scan_source(code)
    assert any(f.rule == 'SENSITIVE_IN_LOG' and 'password' in f.message
               for f in findings)


def test_api_key_leaked_in_print():
    code = (
        'try:\n'
        '    call(api_key)\n'
        'except ConnectionError:\n'
        '    print(f"Failed with {api_key}")\n'
    )
    findings = scan_source(code)
    assert any(f.rule == 'SENSITIVE_IN_LOG' and 'api_key' in f.message
               for f in findings)


def test_bare_except_detected():
    code = (
        'try:\n'
        '    work()\n'
        'except:\n'
        '    print("oops")\n'
    )
    findings = scan_source(code)
    assert any(f.rule == 'BARE_EXCEPT' for f in findings)


def test_sensitive_in_error_response():
    code = (
        'try:\n'
        '    charge(credit_card, amount)\n'
        'except PaymentError:\n'
        '    return {"error": "failed", "card": credit_card}\n'
    )
    findings = scan_source(code)
    assert any(f.rule == 'SENSITIVE_IN_ERROR_RESPONSE'
               and 'credit_card' in f.message for f in findings)


def test_clean_code_no_sensitive_findings():
    code = (
        'try:\n'
        '    process(data)\n'
        'except ValueError as e:\n'
        '    logger.error("Bad input for request %s", request_id)\n'
        '    return {"error": "Invalid input"}\n'
    )
    findings = scan_source(code)
    sensitive = [f for f in findings if f.severity == 'HIGH']
    assert len(sensitive) == 0


def test_cli_exit_code_on_findings(tmp_path):
    vuln = tmp_path / 'vuln.py'
    vuln.write_text(
        'try:\n'
        '    login(password)\n'
        'except Exception:\n'
        '    print(password)\n'
    )
    rc = main([str(vuln), '--format', 'json'])
    assert rc == 1


def test_cli_exit_zero_on_clean(tmp_path):
    clean = tmp_path / 'clean.py'
    clean.write_text(
        'try:\n'
        '    work()\n'
        'except ValueError:\n'
        '    print("error")\n'
    )
    rc = main([str(clean)])
    assert rc == 0
