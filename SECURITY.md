# Security posture

EvilHagrid reads metadata for Kerberos tickets belonging to the calling Windows logon
session. It does not retrieve encoded tickets, session keys, or credentials.

Run it only with explicit authorization. Ticket metadata can still reveal account,
realm, and service names, so protect terminal logs and `pensieve` JSON exports as
sensitive operational data.

The tool does not require elevation and does not accept a logon-session identifier.
Unexpected requests to add raw ticket export, other-session access, credential use,
evasion, or persistence should receive a separate security review.
