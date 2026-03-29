# ike-check

**IKE Cipher Suite Scanner** - enumerate supported cipher suites from an IKE/IPsec peer.

`ike-check` sends IKE negotiation packets to a target and analyzes responses to determine which cipher suites are accepted. It supports both IKEv1 (Main Mode and Aggressive Mode) and IKEv2, classifying each accepted proposal by security level.

## Features

- IKEv1 Main Mode and Aggressive Mode enumeration
- IKEv2 SA_INIT enumeration with DH group sweep
- NAT-Traversal probing (port 4500)
- Security classification of accepted proposals (STRONG, OK, WEAK, INSECURE)
- Multiple output formats: rich console, JSON, plain text
- Quick scan mode for reduced cipher catalog
- Weak-only mode to focus on insecure configurations
- Configurable concurrency, timeouts, and retries

## Installation

```bash
git clone https://github.com/sinkmanu/ike-check.git
cd ike-check
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

```
ike-check <target> [options]
```

**Root privileges are required** for raw socket access.

```bash
sudo ike-check 192.168.1.1
```

### Options

```
usage: ike-check [-h] [-V] [--ike-version {ikev1,ikev2,both}] [-p PORT] [--nat-traversal] [-t TIMEOUT] [-r RETRIES]
                 [--delay DELAY] [--aggressive] [--phase2-infer] [-c CONCURRENCY] [-o {console,json,text}]
                 [--output-file OUTPUT_FILE] [--quick] [--weak-only] [--no-dh-sweep] [-v] [-s SOURCE_IP]
                 target

IKE Cipher Suite Scanner - enumerate supported cipher suites from an IKE peer

positional arguments:
  target                Target IP address or hostname

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  --ike-version {ikev1,ikev2,both}
                        IKE version to probe (default: both)
  -p, --port PORT       Destination port (default: 500)
  --nat-traversal       Also probe on port 4500 (NAT-Traversal)
  -t, --timeout TIMEOUT
                        Timeout per probe in seconds (default: 5)
  -r, --retries RETRIES
                        Retries per probe on timeout (default: 2)
  --delay DELAY         Delay between probes in seconds (default: 0.5)
  --aggressive          Also probe IKEv1 Aggressive Mode
  --phase2-infer        Infer Phase 2 support from Phase 1 results
  -c, --concurrency CONCURRENCY
                        Concurrent probes (default: 1, be careful with rate limiting)
  -o, --output {console,json,text}
                        Output format (default: console)
  --output-file OUTPUT_FILE
                        Write output to file (for json/text formats)
  --quick               Quick scan with reduced cipher suite catalog
  --weak-only           Only probe weak and insecure cipher suites (INSECURE + WEAK security level)
  --no-dh-sweep         Skip DH group sweep and test all groups (slower but more thorough)
  -v, --verbose         Show rejected and timed-out proposals too
  -s, --source-ip SOURCE_IP
                        Source IP address (for multi-homed hosts)
```

### Examples

Quick scan IKEv2 only:

```bash
sudo ike-check 10.0.0.1 --ike-version ikev2 --quick
```

Full scan with Aggressive Mode, JSON output:

```bash
sudo ike-check 10.0.0.1 --aggressive -o json --output-file results.json
```

Hunt for weak configurations:

```bash
sudo ike-check 10.0.0.1 --weak-only -v
```

## Security Levels

Accepted proposals are classified into four levels:

| Level | Meaning |
|-------|---------|
| **STRONG** | Modern, recommended algorithms |
| **OK** | Still considered safe but not ideal |
| **WEAK** | Should be migrated away from |
| **INSECURE** | Broken or deprecated, immediate risk |

## References

This project is based on the following RFCs:

| RFC | Title |
|-----|-------|
| [RFC 2408](https://datatracker.ietf.org/doc/html/rfc2408) | Internet Security Association and Key Management Protocol (ISAKMP) |
| [RFC 2409](https://datatracker.ietf.org/doc/html/rfc2409) | The Internet Key Exchange (IKE) |
| [RFC 4754](https://datatracker.ietf.org/doc/html/rfc4754) | IKE and IKEv2 Authentication Using ECDSA |
| [RFC 5114](https://datatracker.ietf.org/doc/html/rfc5114) | Additional Diffie-Hellman Groups for Use with IETF Standards |
| [RFC 6467](https://datatracker.ietf.org/doc/html/rfc6467) | Secure Password Framework for IKEv2 |
| [RFC 6954](https://datatracker.ietf.org/doc/html/rfc6954) | Using the Elliptic Curve Cryptography (ECC) Brainpool Curves for IKEv2 |
| [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296) | Internet Key Exchange Protocol Version 2 (IKEv2) |
| [RFC 7427](https://datatracker.ietf.org/doc/html/rfc7427) | Signature Authentication in IKEv2 |
| [RFC 7619](https://datatracker.ietf.org/doc/html/rfc7619) | The NULL Authentication Method in IKEv2 |
| [RFC 8247](https://datatracker.ietf.org/doc/html/rfc8247) | Algorithm Implementation Requirements and Usage Guidance for IKEv2 |
| [RFC 9227](https://datatracker.ietf.org/doc/html/rfc9227) | Using GOST Ciphers in IKEv2 |
| [RFC 9370](https://datatracker.ietf.org/doc/html/rfc9370) | Multiple Key Exchanges in IKEv2 |
| [RFC 9385](https://datatracker.ietf.org/doc/html/rfc9385) | Using GOST Cryptographic Algorithms in IKEv2 |
| [RFC 9395](https://datatracker.ietf.org/doc/html/rfc9395) | Deprecation of IKEv1 and Obsoleted Algorithms |

## See Also

- [Setup VPN IPsec in Debian](https://unam.re/blog/setup-vpn-ipsec-in-debian) — background on IPsec/IKE configuration

## Disclaimer

This tool is intended for **authorized security assessments and research only**. Only use it against systems you have explicit permission to test. Unauthorized scanning may violate applicable laws.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## Author
Manuel Mancera (manu@unam.re)

