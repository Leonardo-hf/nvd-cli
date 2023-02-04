### About

A command-line tool that wraps nvdlib (https://github.com/vehemont/nvdlib).

### Help

Usage: nvd.py [OPTIONS]

**Options:**

| --id TEXT                                | Id for CVE, for example: 'CVE-1999-1322'                     |
| ---------------------------------------- | ------------------------------------------------------------ |
| **--key TEXT**                           | Keyword for searching, use '+' to input multiple keywords, for example: 'harmonyos+overflow' |
| **-date TEXT...**                        | Time range for searching, input two date to represent the start and end, and '0' for the present. for example: '2023-10-01 2023-01-01' or '2023-01-01 0'. |
| **--cwe TEXT**                           | CWE for searching, for example: 'CWE-1' or '1’.              |
| **--cvss [critical, high, medium, low]** | CVSS3.1 for searching, the optional range is {'critical', 'high', 'medium' and 'low'}. |
| **--cvss2 [high, medium, low]**          | CVSS2 for searching, the optional range is {'high', 'medium' and 'low'}. |
| **--num INTEGER**                        | Display number, the default is 10 and use any number less than or equal to 0 for all.  [required] |
| **--csv FILENAME**                       | Denote the path to save the output as a CSV.                 |
| **--api TEXT**                           | The NVD API KEY helps you get higher query frequency. You can apply from 'https://nvd.nist.gov/developers/request-an-api-key' and then set the key manually or  put it in an environment variable named  'NVD_KEY'. |
| **--help**                               | Show this message and exit.                                  |

