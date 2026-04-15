# AI-Assisted Contributions Guide

## Overview

This document outlines the guidelines and requirements for contributions that involve AI-generated code in the OpenJCEPlus project. We welcome the use of AI tools to enhance productivity and code quality, while maintaining strict standards for validation and legal compliance.

## General Policy

**AI-generated code is permitted throughout the codebase** with proper validation. All AI-assisted contributions must follow the guidelines outlined in this document to ensure code quality, security, and legal compliance.

**APPROVED AI TOOL**: At this time, only **[Bob](https://bob.ibm.com/)** is approved for use in this project. Use of other AI tools is not permitted.

## Core Principles

While we embrace AI assistance, contributors must ensure:

- **Security**: All code, especially cryptographic implementations, must be thoroughly reviewed and tested
- **Compliance**: Code must be compatible with our project licenses and standards
- **Legal Protection**: AI-generated code must not reproduce copyrighted or improperly licensed code
- **Maintainability**: Code must be clear, well-documented, and understandable by human maintainers
- **Accountability**: Contributors remain fully responsible for all submitted code, regardless of how it was generated

## Where AI Assistance May Be Used

[Bob](https://bob.ibm.com/) may be used for:

- **Cryptographic implementations** (with rigorous validation and testing)
- **Test code and test utilities**
- **Build scripts and automation**
- **Documentation generation and improvement**
- **Code refactoring and optimization**
- **Bug fixes and enhancements**
- **Native interface code (JNI implementations)**
- **Any code in the project**

## Validation Requirements

Before submitting any AI-generated code, you MUST:

### 1. Verify Legal Compliance

- Ensure the code is not copyrighted or licensed outside our [project's license](../LICENSE)
- Check that the code doesn't reproduce proprietary implementations
- Confirm Bob's terms of service allow commercial use and redistribution
- Verify no patent or trademark violations

### 2. Review for Correctness

- **Thoroughly understand** all AI-generated code before submitting
- Test extensively across all supported platforms
- Verify it follows project coding standards ([../style.xml](../style.xml) for Java, [.clang-format](../.clang-format) for C)
- Ensure it doesn't introduce security vulnerabilities
- For cryptographic code: verify against known test vectors and standards

### 3. Security Validation

- Review for common vulnerabilities (buffer overflows, injection attacks, etc.)
- Ensure proper error handling and input validation

### 4. Run All Tests

- Ensure all existing tests pass
- Add appropriate test coverage for new functionality
- Verify the code works across all supported platforms:
  - Linux (aarch64, amd64, s390x, ppc64le)
  - Windows (amd64)
  - AIX (ppc64)
  - Mac OS X (aarch64, amd64)
  - z/OS
- Run performance benchmarks if applicable

## Code Review Process

Pull requests containing AI-generated code will undergo thorough review:

### 1. Automated Checks

- CI/CD pipeline must pass all tests
- Code style checks must pass ([../checkstyle.xml](../checkstyle.xml) for Java, [.clang-format](../.clang-format) for C)
- All platforms must build successfully

### 2. Manual Review

- Verify that only Bob was used (no other AI tools)
- Legal compliance will be assessed
- Code quality and correctness will be evaluated
- Security implications will be carefully reviewed
- For cryptographic code: additional scrutiny for correctness and standards compliance

### 3. Documentation Review

- Ensure all code is properly documented
- Verify code follows project documentation standards

## Best Practices

### DO:

- ✅ Use Bob to enhance productivity and code quality
- ✅ Thoroughly understand and review all Bob-generated code
- ✅ Test extensively on all supported platforms
- ✅ Verify cryptographic implementations against standards and test vectors
- ✅ Follow project coding standards and conventions
- ✅ Add comprehensive test coverage
- ✅ Document your code clearly

### DON'T:

- ❌ Copy-paste Bob code without understanding it
- ❌ **Use any AI tool other than Bob**
- ❌ Assume Bob-generated code is correct without verification
- ❌ Skip testing on any supported platform
- ❌ Submit code that violates licenses or copyrights
- ❌ Ignore security warnings or vulnerabilities
- ❌ Forget to validate cryptographic implementations

## Special Considerations for Cryptographic Code

When using Bob for cryptographic implementations:

2. **Test Vectors**: Validate using known test vectors from standards documents
3. **Side-Channel Resistance**: Review for timing attacks and other side-channel vulnerabilities
4. **Error Handling**: Ensure proper error handling that doesn't leak sensitive information
5. **Memory Management**: Verify proper cleanup of sensitive data
6. **Peer Review**: Cryptographic code should receive additional review from security experts

## Consequences of Non-Compliance

Failure to follow these guidelines may result in:

- Pull request rejection
- Request to remove code generated by unauthorized AI tools
- Delays in code review and acceptance
- In severe cases, contributor access restrictions

## Reporting Issues

If you discover:

- Use of unauthorized AI tools (anything other than Bob)
- Potential license violations
- Security vulnerabilities in AI-generated code
- Code that doesn't meet project standards

Please report it immediately by:

1. Opening an issue in the project repository
2. Contacting project maintainers directly
3. Following our [security policy](../SECURITY.md) for security issues

## Questions?

If you're unsure whether your use of Bob complies with these guidelines:

1. Ask in the pull request comments before submitting
2. Remember: only Bob is approved - do not use other AI tools
3. Consult with project maintainers
4. Review this document and related project policies

## Updates to This Policy

This policy may be updated as AI tools and best practices evolve. Contributors are responsible for staying current with the latest version of this document. Check the git history of this file for recent changes.

## Additional Resources

- [Bob - IBM's AI Assistant](https://bob.ibm.com/)
- [Project License](../LICENSE)
- [Notices and Attributions](../NOTICES.md)
- [Security Policy](../SECURITY.md)
- [Java Style Guide](../style.xml)
- [C Style Guide](../.clang-format)
- [Contributing Guidelines](../README.md#contributions)

---

**Remember**: AI is a tool to enhance your work, not replace your responsibility. You remain fully accountable for all code you submit, regardless of how it was generated. When in doubt, ask!
