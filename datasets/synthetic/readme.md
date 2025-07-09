## prompt used to generate synthetic dataset from LLM . 
### this process is done repeatedly till we get the desired amount of synthetic records.

``` 
Act as a Java security expert specializing in vulnerability classification. Generate a diverse set of Java code samples in JSONL format that clearly demonstrate both vulnerable and secure coding practices. For each sample, provide:

Realistic, syntactically correct Java code (40-200 lines)

Clear classification as VULNERABLE/NOT_VULNERABLE

Specific vulnerability type (CWE number/name for vulnerable cases, "safe" for secure code)

Requirements:

Code Generation:

Include vulnerabilities from OWASP Top 10, SANS 25, and CWE Top 25

Cover these vulnerability types (with examples):

Injection (SQL, OS, LDAP)

Broken Authentication

Sensitive Data Exposure

XXE

Broken Access Control

Security Misconfiguration

XSS

Insecure Deserialization

Using Components with Known Vulnerabilities

Insufficient Logging & Monitoring

Dataset Quality:

60% vulnerable / 40% secure samples

No duplicate code patterns

Varied contexts: web apps, microservices, Android, libraries

Different Java versions (8-17 features)

Multiple coding styles (verbose, concise, functional)

Realistic class/method names

give in the format of 
{
"code":code,
"classification":[VULNERABLE/NOT_VULNERABLE],
"vulnerability_type": specific vulnerability type such as cwe ,
}
```