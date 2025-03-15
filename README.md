<!--
This project is designed to parse and analyze DMARC reports sent by email providers.
DMARC (Domain-based Message Authentication, Reporting, and Conformance) is an email
authentication protocol that helps prevent email spoofing and phishing.

The parser extracts data from XML reports, processes it, and stores it in a database
for analysis. It tracks SPF and DKIM authentication results along with their selectors
to help monitor email authentication compliance over time.

This tool is particularly useful for organizations that want to:
1. Track their DMARC compliance
2. Identify legitimate vs unauthorized senders
3. Monitor authentication trends over time
4. Make informed decisions about DMARC policy adjustments

Future enhancements may include a web interface, automated report fetching from
email accounts, and more advanced visualization capabilities.
-->