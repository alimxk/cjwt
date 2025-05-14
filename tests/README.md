# cjwt Tests

This directory contains unit tests for the `cjwt` tool. The tests cover all the functionality implemented in the main program.

## Prerequisites

Before running the tests, ensure you have the following Python packages installed:

```bash
pip install pytest pyjwt cryptography colorama pyperclip
```

## Test Structure

The tests are organized into several files:

- `test_decode.py` - Tests for JWT decoding functionality
- `test_create_validate.py` - Tests for creating and validating JWTs
- `test_utils_functions.py` - Tests for utility functions
- `test_cli.py` - Tests for command-line interface

## Running the Tests

You can run all tests at once using the provided script:

```bash
cd /path/to/cjwt
python -m tests.run_tests
```

This script will:

1. Set up the test environment (generate necessary test keys and data files)
2. Run all unit tests
3. Report test results

## Running Individual Test Files

You can also run individual test files:

```bash
python -m unittest tests.test_decode
python -m unittest tests.test_create_validate
python -m unittest tests.test_utils_functions
python -m unittest tests.test_cli
```

## Generated Test Data

The test script generates the following test data in the `tests` directory:

### Keys

- RSA key pair (`tests/keys/rsa_private.pem`, `tests/keys/rsa_public.pem`)
- EC key pair (`tests/keys/ec_private.pem`, `tests/keys/ec_public.pem`)
- JWK sample (`tests/keys/test.jwk`)

### JWT Tokens

- Valid JWT (`tests/data/valid_jwt.txt`)
- Expired JWT (`tests/data/expired_jwt.txt`)
- Multiple JWTs (`tests/data/multiple_jwts.txt`)
- RSA signed JWT (`tests/data/rsa_jwt.txt`)
- EC signed JWT (`tests/data/ec_jwt.txt`)

## Test Coverage

The tests cover all major functionality of the `cjwt` tool:

1. JWT decoding and display
2. JWT creation with various algorithms and key types
3. JWT validation and verification
4. Header inspection and claim extraction
5. Expiration checking and modification
6. Format conversion
7. Batch processing

## Adding New Tests

To add new tests:

1. Create a new test file in the `tests` directory named `test_*.py`
2. Import the necessary modules
3. Create a test class that inherits from `unittest.TestCase`
4. Write test methods that start with `test_`
5. Run the tests using the provided script
