0.4.3 Oct 28, 2015:
  o self-repair the keyring if keys get duplicated. Closes: #7498
  o catch request exceptions on key fetching. Closes #7410.
  o Don't repush a public key with different addres
  o use async events api. Closes #7224.
  o Use ca_bundle when fetching keys by url.
  o add logging to fetch_key. Related: #7410.
  o more verbosity in get_key wrong address log.
  o don't repush a public key with different address. Related #7420.

0.4.2 Aug 26, 2015:
  o Style changes.
  o Tests updates.
  o Packaging improvements.

0.4.1 Jul 10, 2015:
  o Remove the dependency on enum34. Closes: #7188.

0.4.0 Jun 8, 2015:
  o Adapt to new events api on leap.common. Related to #5359.
  o Add 'fetch_key' method to fetch keys from a URI. Closes #5932.
  o Clean up API.
  o Fix call to python-gnupg's verify_file() method. Closes #6022.
  o KeyManager.put_key now accepts also ascii keys.
  o Multi uid support. Closes #6212.
  o Port keymanager to the new soledad async API. Closes #6368.
  o Return always KeyNotFound failure if fetch keys fails on an unknown error.
  o Upgrade keys if not successfully used and strict high validation level.
    Closes #6211.
  o Use addresses instead of keys for encrypt, decrypt, sign & verify.
    Closes #6346.
  o Expose info about the signing key. Closes #6366.
  o Fetched keys from other domain than its provider are set as 'Weak Chain'
    validation level. Closes #6815.
  o Keep old key after upgrade. Closes #6262.
  o New soledad doc struct for encryption-keys. Closes #6299.
  o Upgrade key when signed by old key. Closes #6240.

0.3.8 Apr 4, 2014:
  o Properly raise KeyNotFound exception when looking for keys on
    nickserver. Fixes #5415.
  o Do not decode decrypted data, return as str.
  o Use a better version handler for the gnupg version check.
  o Memoize call to get_key. Closes #4784.
  o Update auth to interact with webapp v2. Fixes #5120.

0.3.7 Dec 6, 2013:
  o Fix error return values on openpgp backend.
  o Remove address check when sending email and rely in the email
    client to verify that is correct. Closes #4491.
  o Support sending encrypted mails to addresses using the '+' sign.
  o Improve exception names and handling.

0.3.6 Nov 15, 2013:
  o Default encoding to 'utf-8' in case of system encodings not
    set. Closes #4427.
  o Add verification of detached signatures. Closes #4375.
  o New openpgp method: parse_ascii_keys.
  o Expose openpgp methods in keymanager (parse_ascii_keys, put_key,
    delete_key).

0.3.5 Nov 1, 2013:
  o Return unicode decrypted text to avoid encoding issues. Related to
    #4000.

0.3.4 Oct 18, 2013:
  o Add option to choose cipher and digest algorithms when signing and
    encrypting. Closes #4030.

0.3.3 Oct 4, 2013:
  o Add a sanity check for the correct version of gnupg.
  o Update code to use gnupg 1.2.2 python module. Closes #2342.

0.3.2 Sep 6, 2013:
  o Do not raise exception when a GET request doesn't return 2XX
    code. Nickserver uses error codes for more verbosity in the
    result.
  o Accept unicode ascii keys along with str.

0.3.1 Aug 23, 2013:
  o Signal different key related events, like key generation, key
    upload.
  o Update to new soledad package scheme (common, client and
    server). Closes #3487.
  o Packaging improvements: add versioneer and parse_requirements.

0.3.0 Aug 9, 2013:
  o If a nickserver request fails in any way, notify and continue.
  o Options parameter in gnupg.GPG isn't supported by all versions, so
    removing it for the time being.
  o Add support for bundled gpg. Closes #3397.
  o Refactor API to include encrypt/decrypt/sign/verify in KeyManager.

0.2.0 Jul 12, 2013:
  o Move keymanager to its own package
