# Beheader
A python-based CLI tool that parses HTTP headers to detect the prescence/abscense of security headers(currently tests for 4 security headers)

Currently the tool tests for the following headers and their flags:<br />

**1) Strict-Transport-Security**
- max-age(parses output to find max-age)
- includeSubdomains
- preload

**2) X-Frame-Options**
- deny
- sameorigin

**3) X-Content-Type-Options**
  - nosniff(header only has one associated flag)

**4) Refferer-Policy**
  - no-refferer
  - same-origin
  - strict-origin-when-cross-origin
  - origin-when-cross-origin
  - no-refferer-when-downgrade
  - origin
  - strict-origin
  - unsafe-url
    
To make file executable run 
```
chmod +x beheader.py
```

Usage:
```
./beheader.py -u/--url <URL TO BE SCANNED>
```
