# Python Code Obfuscator

A Python script to obfuscate Python code to protect intellectual property. This script uses encryption and obfuscation techniques to make the code harder to reverse-engineer.

## Features

- **Obfuscation**: Renames variables, functions, and classes to random strings.
- **Encryption**: Encrypts the obfuscated code using AES encryption in GCM mode.
- **Decryption**: Includes a dynamically generated decryption function to execute the encrypted code.
- **Anti-Debugging**: Detects if a debugger is present and aborts execution.
- **Sandbox Check**: Detects if the script is running in a virtual environment.

## Requirements

- Python 3.11+
- `pycryptodome`: For cryptographic functions.
- `colorama`: For colored terminal output.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/biolocated/Bio-Obfuscator.git
    cd your-repository
    ```

2. **Create and activate a virtual environment** (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install the required packages**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the script**:
    ```bash
    python obfuscator.py
    ```

2. **Follow the prompts**:
    - Enter the path to the Python file you want to obfuscate.
    - The obfuscated and encrypted code will be saved to a new file with `-obf.py` suffix.

## Example

Here's an example of how to use the obfuscator:

```bash
python Bio-Obfuscator.py
