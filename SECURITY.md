# Security Findings and Fixes

## Overview
This document summarizes the security vulnerabilities identified and fixed in storage-status.py.

## Vulnerabilities Found and Fixed

### 1. Command Injection via shell=True (CRITICAL)

**Issue:** The code was using `subprocess.run()` with `shell=True` and incorporating external data into command strings without proper validation. This could allow command injection attacks if an attacker could manipulate system state (e.g., create malicious ZFS pool names or network interface names).

**Vulnerable Code Patterns:**
- Using `shell=True` with dynamic command strings
- `f"zpool status {pool_name}"` - pool_name from zpool list output
- `f"systemctl show -p {props} {service}"` - service name from list
- `f"cat /sys/class/net/{name}/speed"` - interface name from ip command output

**Risk:** An attacker who can manipulate pool names, interface names, or other system identifiers could potentially execute arbitrary commands on the system.

**Fixes Applied:**
1. Added `shlex` import for safe command quoting (used in run() method for static commands)
2. Created new `run_safe()` method in `CommandRunner` class that:
   - Uses `shell=False` for local execution
   - Accepts command arguments as a list instead of a string
   - Properly quotes arguments when executing via SSH
3. Created `validate_name()` helper function to validate names against allowed character sets
4. Updated vulnerable code paths:
   - `_parse_pool_status()`: Now uses `run_safe(['zpool', 'status', safe_pool_name])`
   - Network interface speed reading: Uses `run_safe(['cat', path])` with validated names
   - Service status queries: Uses `run_safe()` with argument lists

**Result:** All dynamic data is now either validated or properly escaped before being used in commands.

### 2. DNS Lookup Denial of Service (MODERATE)

**Issue:** The code performs reverse DNS lookups using `socket.gethostbyaddr()` without setting explicit timeouts. This could cause the application to hang if DNS servers are slow or unresponsive.

**Locations:**
- Line 1189: `_resolve_smb_hostnames()` reverse DNS lookup
- Line 1369: `_resolve_hostnames()` reverse DNS lookup

**Risk:** Application could hang for extended periods when DNS servers are slow, causing poor user experience or potential DoS.

**Fixes Applied:**
1. Added 2-second timeout for DNS lookups using `socket.setdefaulttimeout(2.0)`
2. Properly restore original timeout after DNS operations in try-finally blocks
3. Existing exception handling already catches `socket.timeout` exceptions

**Result:** DNS lookups now have a reasonable timeout, preventing hanging on slow DNS servers.

## Security Best Practices Implemented

1. **Input Validation:** All external data (pool names, interface names, service names) is validated against expected patterns before use using `validate_name()`
2. **Safe Command Execution:** Commands with dynamic data use argument lists (`shell=False`) instead of string interpolation via `run_safe()`
3. **Proper Quoting:** When shell execution is necessary (for static commands), all dynamic values are properly quoted using `shlex.quote()`
4. **Timeout Protection:** Network operations (DNS lookups, subprocess calls) have appropriate timeouts
5. **Error Handling:** All potentially dangerous operations are wrapped in try-except blocks
6. **Path Traversal Protection:** File paths are validated using `os.path.realpath()` to prevent directory traversal attacks

## Remaining shell=True Usage

The `CommandRunner.run()` method still uses `shell=True`, but this is now only used for static command strings that require shell features (pipes, redirects). All commands with dynamic data now use the safer `run_safe()` method.

**Static commands using run():**
- `"zpool list -H -o name,size,alloc,free,cap,health,dedup,frag"`
- `"zfs list -H -o name,used,avail,refer,..."`
- `"cat /proc/loadavg"`
- `"ip -br addr | grep -v '^lo'"` (pipe)
- `"smbstatus --json 2>/dev/null"` (redirect)
- And other similar static command strings

These are safe because they contain no user-controlled data.

## CodeQL Analysis Results

After applying all fixes, CodeQL analysis found **0 security alerts**.

## Testing Recommendations

1. Test with malicious pool names containing shell metacharacters
2. Test with malicious network interface names
3. Test DNS lookup timeout behavior with slow DNS servers
4. Verify all functionality still works correctly after security fixes

## Conclusion

All identified security vulnerabilities have been addressed. The code now properly:
- Validates and sanitizes external data before use in commands
- Uses safe command execution methods for dynamic data
- Implements appropriate timeouts for network operations
- Maintains backward compatibility with existing functionality
