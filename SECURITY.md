# Security Policy

## Overview

Nullifier.cash is a privacy mixer on Solana that handles user funds. Security is our top priority. This document outlines our security practices, known considerations, and how to report vulnerabilities.

## Security Features

### Smart Contract Security

1. **Time-Lock Enforcement**
   - Minimum 1-hour delay between deposit and withdrawal
   - Prevents immediate withdrawal attacks
   - Enforced at the smart contract level

2. **Emergency Pause**
   - Authority can pause deposits and withdrawals
   - Protects users in case of discovered vulnerabilities
   - Can be triggered instantly

3. **Access Controls**
   - Multi-signature authority support
   - Separate roles for authority and fee collector
   - Protected admin functions

4. **Input Validation**
   - Fixed denominations only (1, 10, 100 SOL)
   - Minimum time delay enforcement
   - Pool validation on all operations

5. **State Management**
   - Withdrawal state tracking prevents double-withdrawal
   - Pool statistics for monitoring
   - Timestamp verification

### Solana-Specific Security

1. **PDA Seeds**
   - Deterministic PDA generation
   - Prevents account confusion attacks
   - Canonical bump seeds stored

2. **Account Validation**
   - Proper account ownership checks
   - Seeds validation on all PDAs
   - Signer verification

3. **Rent Exemption**
   - All accounts rent-exempt
   - Prevents account closure attacks

4. **Compute Budget**
   - Optimized for Solana's compute limits
   - No unbounded loops
   - Efficient state updates

## Known Considerations

### Privacy Limitations

1. **Anonymity Set Size**
   - Privacy depends on pool usage
   - Small pools = less privacy
   - Recommend waiting for larger anonymity sets

2. **Timing Analysis**
   - Minimum delay is fixed at 1 hour
   - Users should vary withdrawal times
   - Future versions will support variable delays

3. **Amount Correlation**
   - Fixed denominations prevent amount correlation
   - Multiple deposits recommended for large amounts

### Smart Contract Limitations

1. **Time Manipulation**
   - Relies on Solana Clock sysvar
   - Validators cannot manipulate timestamps significantly
   - 1-hour delay provides sufficient buffer

2. **Authority Risk**
   - Initial authority has significant power
   - Mitigation: Transfer to multi-sig immediately
   - Future: Full DAO governance

3. **Upgrade Risk**
   - Program is upgradeable by authority
   - Mitigation: Multi-sig + time-lock on upgrades
   - Future: Immutable after DAO transition

## Security Best Practices

### For Users

1. **Withdrawal Safety**
   - Always withdraw to a fresh, unused address
   - Never reuse deposit addresses
   - Use multiple smaller deposits for large amounts

2. **Operational Security**
   - Use VPN or Tor when interacting
   - Clear browser data after use
   - Don't link deposit/withdrawal addresses

3. **Timing**
   - Wait longer than minimum delay when possible
   - Vary withdrawal times
   - Don't withdraw immediately after delay expires

4. **Pool Selection**
   - Check anonymity set size before depositing
   - Use pools with more active deposits
   - Consider multiple smaller amounts

### For Operators

1. **Authority Management**
   - Use hardware wallets for all keys
   - Implement multi-signature immediately
   - Regular key rotation procedures

2. **Monitoring**
   - 24/7 monitoring of contract activity
   - Alert on anomalous patterns
   - Regular audit of pool balances

3. **Upgrade Procedures**
   - Thorough testing before any upgrade
   - Community notification period
   - Emergency rollback plan

4. **Incident Response**
   - Documented response procedures
   - Emergency contacts list
   - Clear escalation paths

## Audits

### Pre-Mainnet Requirements

- [ ] Audit by Trail of Bits or similar (Tier 1)
- [ ] Audit by OtterSec or similar (Tier 2)
- [ ] Internal security review
- [ ] Formal verification (where applicable)

### Audit Scope

Audits should cover:
- Smart contract logic
- Access control mechanisms
- Time-lock implementation
- Pool accounting
- Emergency procedures
- Upgrade mechanisms
- Common vulnerabilities (reentrancy, overflow, etc.)

## Bug Bounty Program

### Scope

In scope:
- Smart contract vulnerabilities
- Logic errors allowing fund theft
- Bypassing time-lock mechanisms
- Admin privilege escalation
- Pool accounting errors

Out of scope:
- UI/UX issues (unless security-critical)
- Gas optimization suggestions
- Known limitations documented here
- Third-party dependencies

### Severity Levels

**Critical (Up to $50,000)**
- Direct theft of user funds
- Bypassing time-lock completely
- Unauthorized admin access

**High (Up to $10,000)**
- Partial fund theft
- Privacy breach mechanisms
- Time-lock reduction exploits

**Medium (Up to $2,000)**
- Denial of service
- Pool statistics manipulation
- Minor logic errors

**Low (Up to $500)**
- Informational issues
- Code quality concerns
- Optimization opportunities

## Vulnerability Disclosure

### How to Report

If you discover a security vulnerability:

1. **DO NOT** publicly disclose the issue
2. Email: security@nullifier.cash (PGP key provided)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **24 hours**: Initial response
- **72 hours**: Severity assessment
- **7 days**: Fix developed and tested
- **14 days**: Fix deployed (critical issues)
- **30 days**: Public disclosure (after fix)

### Safe Harbor

We commit to:
- Not pursue legal action for good faith security research
- Work with you to understand and fix the issue
- Recognize your contribution publicly (if desired)
- Pay bounties promptly for valid vulnerabilities

## Security Checklist

### Pre-Launch

- [ ] Complete security audits
- [ ] Bug bounty program active
- [ ] Multi-sig authority set up
- [ ] Emergency procedures tested
- [ ] Monitoring systems live
- [ ] Incident response plan documented
- [ ] Community notification prepared

### Ongoing

- [ ] Regular security reviews
- [ ] Continuous monitoring
- [ ] Prompt vulnerability response
- [ ] Regular dependency updates
- [ ] Community security education

## Known Vulnerabilities

Currently, there are no known critical vulnerabilities. This section will be updated as issues are discovered and resolved.

## Responsible Disclosure

We believe in responsible disclosure and will:
- Acknowledge reporters within 24 hours
- Provide regular updates on fix progress
- Credit reporters appropriately (unless anonymous preferred)
- Pay bounties for valid vulnerabilities
- Publish post-mortems for significant issues

## Contact

- **Security Email**: security@nullifier.cash
- **PGP Key**: [To be published]
- **Discord**: [To be published]
- **Emergency Contact**: [To be published]

## Updates

This security policy is updated regularly. Last update: [To be set on deployment]

---

**Remember**: Security is everyone's responsibility. If you see something, say something.
