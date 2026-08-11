# Glider Security Queries

A curated collection of Glider queries for detecting smart contract vulnerabilities. Designed for bug bounty hunting, security audits, and contributing to the [Glider Query Database](https://r.xyz/glider-query-database).

## Repository Structure

```
glider-security-queries/
├── queries/
│   ├── delegatecall/
│   │   └── unchecked_delegatecall_return.py      # Delegatecall return validation
│   ├── reentrancy/
│   │   └── unguarded_external_calls.py           # Reentrancy via state changes after calls
│   ├── access-control/
│   │   └── missing_access_control.py             # Missing authorization on sensitive functions
│   ├── unchecked-calls/
│   │   └── unchecked_low_level_calls.py          # call/delegatecall/staticcall without validation
│   ├── integer-overflow/
│   │   └── unchecked_arithmetic.py               # Arithmetic overflow/underflow
│   ├── governance/
│   │   └── unchecked_proposal_execution.py       # Governance execution without validation
│   ├── proxy-patterns/
│   │   └── unchecked_proxy_upgrade.py            # Proxy upgrades without init validation
│   └── oracle-manipulation/
│       └── single_oracle_no_validation.py        # Oracle price manipulation risks
├── examples/
│   └── VulnerablePatterns.sol                    # Test contracts for each vulnerability
├── tests/
│   └── GliderQueryTests.t.sol                    # Foundry tests confirming vulnerabilities
├── docs/
│   ├── CONTRIBUTING.md                           # Contribution guidelines
│   ├── QUERY_TEMPLATE.md                         # Template for new queries
│   └── TESTING.md                                # Testing guide
├── scripts/
│   ├── run_all_queries.py                        # Batch query runner
│   └── validate_queries.py                       # Query syntax validator
├── .github/workflows/
│   └── glider-scan.yml                           # CI/CD for query validation
├── README.md
├── requirements.txt
└── pyproject.toml
```

## Quick Start

### Installation

```bash
git clone https://github.com/palontologist/glider-security-queries.git
cd glider-security-queries
pip install -r requirements.txt
```

### Run Queries with Glider

```bash
# Run single query
glider run queries/delegatecall/unchecked_delegatecall_return.py --target ./examples

# Run all queries
python scripts/run_all_queries.py --target ./examples --output results/

# Validate query syntax
python scripts/validate_queries.py
```

### Run Foundry Tests

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Run tests
forge test -vv
```

## Query Categories

| Category | Queries | Description |
|----------|---------|-------------|
| **Delegatecall** | 1 | Unchecked delegatecall return values (SWC-112) |
| **Reentrancy** | 1 | State changes after external calls (SWC-107) |
| **Access Control** | 1 | Missing authorization on sensitive functions (SWC-105) |
| **Unchecked Calls** | 1 | call/delegatecall/staticcall without validation (SWC-104, SWC-112) |
| **Integer Overflow** | 1 | Arithmetic without overflow protection (SWC-101) |
| **Governance** | 1 | Proposal execution without quorum/state validation |
| **Proxy Patterns** | 1 | Upgrades without initialization validation |
| **Oracle Manipulation** | 1 | Single oracle without deviation/staleness checks |

## Vulnerability Coverage

### SWC Registry Mapping

| SWC ID | Vulnerability | Query |
|--------|---------------|-------|
| SWC-101 | Integer Overflow/Underflow | `unchecked_arithmetic.py` |
| SWC-104 | Unchecked Call Return Value | `unchecked_low_level_calls.py` |
| SWC-105 | Unprotected Ether Withdrawal | `missing_access_control.py` |
| SWC-107 | Reentrancy | `unguarded_external_calls.py` |
| SWC-112 | Delegatecall Return Value | `unchecked_delegatecall_return.py` |

### OWASP Smart Contract Top 10

| Rank | Vulnerability | Covered |
|------|---------------|---------|
| 1 | Access Control | ✅ |
| 2 | Reentrancy | ✅ |
| 3 | Arithmetic Issues | ✅ |
| 4 | Unchecked Return Values | ✅ |
| 5 | Oracle Manipulation | ✅ |
| 6 | Governance Issues | ✅ |
| 7 | Proxy/Upgrade Issues | ✅ |
| 8 | - | - |
| 9 | - | - |
| 10 | - | - |

## Contributing

### Adding New Queries

1. **Create query file** in appropriate category folder
2. **Follow template** in `docs/QUERY_TEMPLATE.md`
3. **Add test cases** in `examples/VulnerablePatterns.sol`
4. **Add Foundry tests** in `tests/GliderQueryTests.t.sol`
5. **Run validation** `python scripts/validate_queries.py`
6. **Submit PR** with description of vulnerability detected

### Query Requirements

- [ ] Proper docstring with title, description, tags, references
- [ ] Handles edge cases (assembly, simulation functions, library patterns)
- [ ] Includes known limitations in comments
- [ ] Tested against vulnerable and safe patterns
- [ ] Follows Glider best practices

### Submitting to Glider Query Database

1. Test query in [Glider IDE](https://glide.r.xyz/ide)
2. Click "Submit to Database" in IDE
3. Query gets rarity rating and joins community database

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/glider-scan.yml`):

- Validates query syntax on every push
- Runs queries against example contracts
- Executes Foundry tests
- Uploads SARIF results to GitHub Security tab
- Scheduled weekly scans

## Resources

- [Glider Documentation](https://glide.gitbook.io/main/)
- [Glider Cheatsheet](https://glide.gitbook.io/main/glider-ide/glider-the-basics/glider-cheatsheet)
- [SWC Registry](https://swcregistry.io/)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
- [Glider Query Database](https://r.xyz/glider-query-database)

## License

MIT License - Free to use, modify, and contribute.

## Acknowledgments

- [Hexens](https://hexens.io/) for Glider framework
- Security research community for vulnerability patterns
- Contributors to the Glider Query Database