0.4.1 - 18 Apr, 2016
+++++++++++++++++++++

Features
~~~~~~~~
- `#7656 <https://leap.se/code/issues/7656>`_: Emit multi-user aware events.
- `#4008 <https://leap.se/code/issues/4008>`_: Add token-based authentication to local IMAP/SMTP services.
- `#7889 <https://leap.se/code/issues/7889>`_: Use cryptography instead of pycryptopp to reduce dependencies.
- `#7263 <https://leap.se/code/issues/7263>`_: Implement local bounces to notify user of SMTP delivery errors.
- Use twisted.cred to authenticate IMAP/SMTP users.
- Verify plain text signed email.
- Validate signature with attachments.
- Use fingerprint instead of key_id to address keys.


Bugfixes
~~~~~~~~
- `#7861 <https://leap.se/code/issues/7861>`_: Use the right succeed function for passthrough encrypted email.
- `#7898 <https://leap.se/code/issues/7898>`_: Fix IMAP fetch headers
- `#7977 <https://leap.se/code/issues/7977>`_: Decode attached keys so they are recognized by keymanager.
- `#7952 <https://leap.se/code/issues/7952>`_: Specify openssl backend explicitely.
- Fix the get_body logic for corner-cases in which body is None (yet-to-be synced docs, mainly).
- Let the inbox used in IncomingMail notify any subscribed Mailbox.
- Adds user_id to Account (fixes Pixelated mail leakage).

Misc
~~~~
- Change IMAPAccount signature, for consistency with a previous Account change.
