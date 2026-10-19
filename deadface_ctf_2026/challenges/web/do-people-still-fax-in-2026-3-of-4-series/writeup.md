# Do People Still Fax in 2026?  (3 of 4 series)

- **Category:** Web
- **Points:** 100
- **Flag:** `deadface{someone_should_report_this}`

## Challenge

Ah yes, websites with documents. Exposure of files are always nasty little vulnerabilities. Think you can find a document that doesn't belong to you? Head back to http://45.79.200.170:3000. > NOTE: Do not perform port scanning on this host, only the address and port discovered in OSINT matter. Submit the flag as: `deadface{flag-text}` http://45.79.200.170:3000/

## Solution

Document exposure through an undocumented route. The application ships an OpenAPI specification at /api-docs whose generated bundle lists a document-download endpoint not referenced anywhere in the UI, taking a document id in the query string and a department identifier in the body. Access control compares the declared department against the DOCUMENT's department rather than against the caller's token, and the response codes form an oracle: 403 means the document exists but belongs elsewhere, 404 means it does not exist. The specification prose also notes the store holds at most a thousand files, which bounds the identifier range. Walking that range finds a record outside the caller's department whose clinical notes carry an incident reference token. A caution worth recording: that document contains TWO flag-shaped strings, and the prominent one in the diagnosis field is the already-solved flag from stage two.
