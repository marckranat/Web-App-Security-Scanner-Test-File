# Web App Security Scanner Test File

This PHP file is designed to test web application / server-side antivirus and security scanners by containing multiple suspicious patterns that are commonly associated with malicious code. **This file contains NO actual malicious code** - all suspicious patterns are stored as strings or are harmless operations.

## Why This File Triggers Scanners

Security scanners use pattern matching, heuristics, and behavioral analysis to detect potential threats. This file intentionally includes many red flags that legitimate security software looks for, even though none of the code is actually malicious.

## Section-by-Section Breakdown

### JavaScript in Multiple Locations (Lines 18-34)

**Why it looks malicious:**
- JavaScript in the `<head>` section with obfuscated variable names (`_0x4f3a`, `_0x2b1c`) is a common technique used by malware to hide malicious code
- The function uses XOR operations (`_0x1a2d^_0x3e4f`) which is frequently used for deobfuscation
- JavaScript in the `<body>` with base64-encoded strings (`atob()`) is a red flag - attackers often encode payloads to evade detection
- The presence of `eval` in variable names suggests code execution attempts

**What it actually does:** Nothing harmful - just defines variables and functions that are never called with malicious input.

### Multiple Encoding Layers (Lines 37-53)

**Why it looks malicious:**
- **Base64 encoding** (`ZXZhbCgnZWNobyAiSGVsbG8gV29ybGQiOycpOw==`): Attackers use base64 to hide malicious code from static analysis
- **Hex encoding** (`6576616c28...`): Another obfuscation technique to bypass pattern matching
- **Double base64**: Multiple layers of encoding are a strong indicator of evasion attempts
- **ROT13 + Base64**: Combining multiple encoding methods is a sophisticated obfuscation technique
- The decoded strings contain `eval()` calls, which is a major red flag

**What it actually does:** Decodes the strings but never executes them - they're just stored in variables.

### Suspicious Function Names (Lines 56-74)

**Why it looks malicious:**
- Lists of dangerous PHP functions (`eval`, `exec`, `system`, `shell_exec`, etc.) are exactly what scanners look for
- `eval()` - executes arbitrary PHP code (highest risk)
- `exec()`, `system()`, `shell_exec()` - execute system commands
- `file_get_contents()`, `fopen()` - file operations that could read sensitive data
- `curl_exec()` - network operations that could exfiltrate data
- `base64_decode()`, `gzinflate()`, `str_rot13()`, `hex2bin()` - deobfuscation functions
- The code string concatenation pattern (`implode('(', $suspicious_functions)`) looks like dynamic function construction

**What it actually does:** Just creates an array and a string - never actually calls any of these functions.

### File Operations (Lines 77-80)

**Why it looks malicious:**
- `file_get_contents(__FILE__)` reading the current file is suspicious - malware often reads itself to replicate or analyze
- File operations combined with encoding/decoding suggest data exfiltration attempts

**What it actually does:** Harmlessly reads the file size and content for display purposes only.

### Network Operations (Lines 83-84)

**Why it looks malicious:**
- `parse_url()` and `gethostbyname()` suggest network connectivity attempts
- Malware often uses these functions to connect to command & control servers
- Even though it's just parsing localhost, the pattern matches malicious behavior

**What it actually does:** Just parses a harmless example URL and resolves localhost - no actual network connections.

### Obfuscated Variable Names (Lines 87-88)

**Why it looks malicious:**
- Using `chr()` to construct variable names dynamically (`${chr(95).chr(120)...}`) is a common obfuscation technique
- Hex-encoded variable names (`\x5f\x30\x78...`) hide the actual variable name from static analysis
- Variable variables (`$$var_name`) make code harder to analyze

**What it actually does:** Just creates some test variables with obfuscated names.

### Dynamic Function Calls (Lines 91-92)

**Why it looks malicious:**
- Concatenating function names (`'base' . '64' . '_' . 'decode'`) is used to hide function calls from static analysis
- Scanners look for this pattern because it's a common evasion technique
- Calling the function dynamically makes it harder for scanners to detect what's being executed

**What it actually does:** Decodes a harmless "Hello" string - no malicious input.

### Nested Encoding (Line 95)

**Why it looks malicious:**
- Combining multiple encoding methods (`base64_encode(gzcompress(str_rot13(hex2bin(...))))`) is a sophisticated evasion technique
- Each layer makes it harder for scanners to detect the final payload
- This pattern is almost exclusively used by malware

**What it actually does:** Just encodes a harmless string through multiple layers.

### Injection Patterns (Lines 98-110)

**Why it looks malicious:**
- **PHP code injection**: `eval($_POST["cmd"])`, `system($_GET["x"])` - classic web shell patterns
- **XSS patterns**: `<script>document.cookie</script>`, `javascript:alert(1)` - cross-site scripting attempts
- **SQL injection**: `'; DROP TABLE users; --` - database attack pattern
- **Command injection**: `; cat /etc/passwd` - system command execution attempt
- These exact strings are in most security scanner signature databases

**What it actually does:** All stored as strings - never executed or used in any context.

### Closures with Encoding (Lines 121-129)

**Why it looks malicious:**
- Closures that decode and transform data are commonly used to hide malicious payloads
- The pattern of `base64_decode()` → `str_rot13()` → `bin2hex()` suggests multi-stage deobfuscation
- This is a sophisticated evasion technique

**What it actually does:** Just transforms a harmless string and returns it - no execution.

### Encoded Function Names (Lines 132-139)

**Why it looks malicious:**
- Encoding function names like `eval`, `exec`, `system` is a red flag
- Attackers encode these to bypass signature-based detection
- The array contains multiple encoded dangerous function names

**What it actually does:** Just creates an array of encoded strings - never used.

### Reflection API (Lines 142-143)

**Why it looks malicious:**
- Reflection API can be used to dynamically call functions, bypassing static analysis
- Accessing function names through reflection is a common obfuscation technique
- Scanners flag reflection usage as potentially suspicious

**What it actually does:** Just gets the name of a function - no dynamic invocation.

### Variable Variables (Lines 146-148)

**Why it looks malicious:**
- Variable variables (`$$var_name`) make code harder to analyze statically
- Dynamic variable construction is used to hide data flow
- Combined with encoding, this is a strong evasion indicator

**What it actually does:** Just creates some test variables.

### Callback Functions (Lines 151-162)

**Why it looks malicious:**
- Arrays of deobfuscation functions (`base64_decode`, `str_rot13`, etc.) suggest payload decoding
- Checking if functions exist before using them is a common malware technique
- This pattern suggests the code might dynamically decode and execute payloads

**What it actually does:** Just checks if functions exist - never calls them on user input.

### Serialization (Lines 165-166)

**Why it looks malicious:**
- Serialized data can hide malicious code that gets executed during `unserialize()`
- PHP object injection attacks use serialization
- Storing function names and code in serialized format is suspicious
- The `unserialize()` function is flagged by many scanners

**What it actually does:** Just serializes and unserializes harmless data - no object injection.

### Regex Pattern Matching (Lines 169-186)

**Why it looks malicious:**
- Regular expressions matching dangerous patterns (`/eval\s*\(/i`, `/exec\s*\(/i`) suggest the code is looking for or constructing malicious code
- Matching superglobal variables (`$_POST`, `$_GET`, `$_REQUEST`) suggests user input handling
- This pattern could indicate code that searches for or builds exploit strings

**What it actually does:** Just checks if patterns exist in a string - no execution.

## Summary

This file is essentially a "greatest hits" collection of patterns that security scanners look for. Each section represents a different category of suspicious behavior:

1. **Obfuscation techniques** (encoding, variable obfuscation)
2. **Dangerous function usage** (eval, exec, system)
3. **File and network operations** (reading files, network calls)
4. **Injection patterns** (XSS, SQL injection, command injection)
5. **Dynamic code execution** (reflection, callbacks, closures)
6. **Data hiding** (serialization, nested encoding)

The key point is that **all of these patterns are present, but none are actually executed maliciously**. This makes it an ideal test file for security scanners - it should trigger alerts while being completely safe to run.

## Usage

Upload this file to your server and check if your security scanner detects it. The file is harmless and can be safely executed, but it should trigger most security scanners due to the numerous suspicious patterns it contains.

## Note

This file is for **testing purposes only**. It is designed to help you verify that your security scanners are working correctly. It should not be used for any malicious purposes.
