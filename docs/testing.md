# Testing Guide

## Overview

WebhookGuard includes tests to verify webhook signature validation and help ensure that incoming requests are handled securely.

## Test Scenarios

The tests cover the following scenarios:

- **Valid signatures:** Verify that legitimate webhook requests are accepted.
- **Tampered payloads:** Check that modified payloads fail signature verification.
- **Invalid signatures:** Ensure that forged signatures are rejected.
- **Replay detection:** Test whether repeated requests are handled according to the implemented replay protection.

## Running Tests

Run the test suite from the project root:

```bash
pytest tests/ -v
```

The `-v` option displays the individual tests and their results.

## Expected Results

Tests should pass when the implementation behaves as expected. If a test fails, review the error output and investigate the relevant validation logic.

