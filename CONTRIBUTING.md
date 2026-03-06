# Contributing to SAP S/4HANA RISE Security Scanner

Thanks for your interest in contributing! This guide will help you get started.

## How to Contribute

### Reporting Issues
- Use GitHub Issues to report bugs or request features
- Include the Python version, OS, and sample data (anonymized) if reporting a bug
- For security vulnerabilities in the scanner itself, please open an issue with the `security` label

### Adding New Checks

1. **Identify the right module:**
   - `user_auth_audit.py` — Basic user/profile checks
   - `iam_advanced.py` — SoD, firefighter, role lifecycle, cross-system identity
   - `security_params.py` — Profile parameter baseline validation
   - `network_services.py` — RFC, ICF, transport, audit log checks
   - `rise_btp_checks.py` — RISE/BTP-specific checks

2. **Follow the pattern** — each check method should:
   - Check if required data is available (`if not data: return`)
   - Iterate through relevant records
   - Call `self.finding()` with all required fields for each issue found

3. **Use proper severity levels:**
   - `CRITICAL` — Immediate exploitation risk, system compromise possible
   - `HIGH` — Significant security gap, exploitation likely with moderate effort
   - `MEDIUM` — Security weakness, defense-in-depth concern
   - `LOW` — Minor hardening opportunity, informational

4. **Include remediation** — every finding should have actionable fix instructions

5. **Add references** — SAP Notes, CIS Benchmark section numbers, or relevant docs

### Adding a New Audit Module

1. Create a new file in `modules/` extending `BaseAuditor`
2. Implement `run_all_checks()` returning a list of findings
3. Add required data file mappings to `DataLoader.FILE_MAP`
4. Register the module in `sap_scanner.py` main flow
5. Update `README.md` with the new module's checks

### Code Style
- Python 3.8+ compatible (no walrus operator, etc.)
- Type hints encouraged
- Docstrings on all classes and public methods
- No external dependencies — stdlib only for core scanner

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check-xyz`)
3. Add/modify checks with test data in `sample_data/`
4. Run the scanner against sample data to verify
5. Update README if adding new checks or modules
6. Submit a PR with a clear description

## Development Setup

```bash
git clone https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner.git
cd SAP-S4HANA-RISE-Security-Scanner

# Verify it runs
python sap_scanner.py --data-dir ./sample_data --output test_report.html

# Run specific modules during development
python sap_scanner.py --data-dir ./sample_data --modules iam --output test.html
```

## Important Notes

- **Never commit real SAP data** — always anonymize exports before using as test data
- **Keep zero-dependency** — the scanner should run on any Python 3.8+ installation without pip installs
- **Test with sample data** — verify your changes produce expected findings with the included sample data
