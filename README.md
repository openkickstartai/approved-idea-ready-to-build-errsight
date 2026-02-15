# ErrSight — Error Path Security Auditor

Static analysis tool that detects sensitive data leakage in Python error handling paths.

Finds passwords, tokens, API keys, and PII exposed through:
- `logging` / `print` calls inside `except` blocks
- Error responses returned to clients from exception handlers
- Bare `except:` clauses that mask critical exceptions

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single file
python main.py app.py

# Scan a directory recursively
python main.py src/

# JSON output for CI integration
python main.py --format json src/

# Fail CI on MEDIUM+ severity
python main.py --fail-on MEDIUM src/
```

## Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `SENSITIVE_IN_LOG` | HIGH | Sensitive variable used in log/print inside error handler |
| `SENSITIVE_IN_ERROR_RESPONSE` | HIGH | Sensitive variable returned from error handler |
| `BARE_EXCEPT` | MEDIUM | Bare `except:` catches all exceptions |

## Detected Sensitive Patterns

`password`, `secret`, `token`, `api_key`, `private_key`, `credential`,
`ssn`, `credit_card`, `card_number`, `cvv`, `pin`, `auth_token`, `session_id`

## Run Tests

```bash
pytest test_errsight.py -v
```

## License

MIT
