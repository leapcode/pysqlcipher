=================
Soledad Documents
=================

KeyManager uses two types of documents for the keyring:

* key document, that stores each gpg key.

* active document, that relates an address to its corresponding key.


Each key can have 0 or more active documents with a different email address
each:

::

  .-------------.          .-------------.
  | foo@foo.com |          | bar@bar.com |
  '-------------'          '-------------'
         |                        |     
         |      .-----------.     |     
         |      |           |     |     
         |      |    key    |     |     
         '----->|           |<----'
                |           |     
                '-----------'


Fields in a key document:

* uids

* fingerprint

* key_data

* private. bool marking if the key is private or public

* length

* expiry_date

* refreshed_at

* version = 1

* type = "OpenPGPKey"

* tags = ["keymanager-key"]


Fields in an active document:

* address

* fingerprint

* private

* validation

* last_audited_at

* encr_used

* sign_used

* version = 1

* type = "OpenPGPKey-active"

* tags = ["keymanager-active"]


The meaning of validation, encr_used and sign_used is related to the `Transitional Key Validation`_

.. _Transitional Key Validation: https://leap.se/en/docs/design/transitional-key-validation
