# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2014 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
Tests for the Validation Levels
"""

from datetime import datetime

from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import (
    KeyNotValidUpgrade
)
from leap.keymanager.tests import (
    KeyManagerWithSoledadTestCase,
    ADDRESS,
    PUBLIC_KEY,
    KEY_FINGERPRINT
)
from leap.keymanager.validation import ValidationLevel


class ValidationLevelTestCase(KeyManagerWithSoledadTestCase):

    def test_none_old_key(self):
        km = self._key_manager()
        km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        key = km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, KEY_FINGERPRINT)

    def test_cant_upgrade(self):
        km = self._key_manager()
        km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS,
                       validation=ValidationLevel.Provider_Trust)
        self.assertRaises(KeyNotValidUpgrade, km.put_raw_key, UNRELATED_KEY,
                          OpenPGPKey, ADDRESS)

    def test_fingerprint_level(self):
        km = self._key_manager()
        km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS,
                       validation=ValidationLevel.Fingerprint)
        key = km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, UNRELATED_FINGERPRINT)

    def test_expired_key(self):
        km = self._key_manager()
        km.put_raw_key(EXPIRED_KEY, OpenPGPKey, ADDRESS)
        km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS)
        key = km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, UNRELATED_FINGERPRINT)

    def test_expired_fail_lower_level(self):
        km = self._key_manager()
        km.put_raw_key(EXPIRED_KEY, OpenPGPKey, ADDRESS,
                       validation=ValidationLevel.Third_Party_Endorsement)
        self.assertRaises(
            KeyNotValidUpgrade,
            km.put_raw_key,
            UNRELATED_KEY,
            OpenPGPKey,
            ADDRESS,
            validation=ValidationLevel.Provider_Trust)

    def test_roll_back(self):
        km = self._key_manager()
        km.put_raw_key(EXPIRED_KEY_UPDATED, OpenPGPKey, ADDRESS)
        km.put_raw_key(EXPIRED_KEY, OpenPGPKey, ADDRESS)
        key = km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.expiry_date, EXPIRED_KEY_NEW_EXPIRY_DATE)


# Key material for testing

# key 901FBCA5: public key "Leap Test Key <leap@leap.se>"
UNRELATED_FINGERPRINT = "ABCCD9C8270B6A8D5633FAC9D04DB2E4901FBCA5"
UNRELATED_KEY = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFQ9VDoBCACbKflcEhUXZULOT4Fwc2ifRUllJpusd2uX5oeDlZdZ15uLY2eF
LcxnAdIWkI/PsXimh0ev/Pf4oCynfmt02I3c2d9F0N6JXWnRiP+p098oPOcqeEqL
N3CrkH1RVnEXNeJ/Fu7tkD61SBXl1MytMfcHyhN5arg8OcVAjcmghX53+92jFhC9
8ss87H/qEe5vEX/ahP3tiL5ULvaS4GIX+XB0O3yCVdRoRG9lqMIBP/ZqCkKrNll8
dT12a6ByG/rWharZUeUETiM4Y+JjDUUaEC2YhNF9k52JNGanLH9LTTtlKy5WTT+E
C6T6VMAtkwcBDpkXr5sBB/N+Y1z0Fp359lIXABEBAAG0HExlYXAgVGVzdCBLZXkg
PGxlYXBAbGVhcC5zZT6JATgEEwECACIFAlQ9VDoCGwMGCwkIBwMCBhUIAgkKCwQW
AgMBAh4BAheAAAoJENBNsuSQH7ylsSUIAIxUFbkeTdHbCF/LVA2U+ktnR1iVikAY
vFK+U+Bto11/AO4Kew2eWniDch/sqLQOoSydtP42z2z3/Al3u7LhQ8bElQHPDY78
t49qweyJi00V3vCKCdWwPJnPM5eJOIrZHCbwIgeXCsXxVNJVyziVqMuum+px1h2d
1YJZXYejT8rzwa3yBPAsGWRAWETeTvUuyjPMFa59scbnaDuY+bwQ2r/qG9m7UyHU
h2kAHC5sf1rixVOY6rLhw75gQHE/L2BZJRfVsDQqIpEMh2OgMfNbL928jncjwQvc
/IXXwSUx7y50ll+uNh+TVLf0MlUjKdHmHqnGBMlIIWojWJuKxYmOOoO5AQ0EVD1U
OgEIAM/TlhWVSI+tl5XBUAcf60RxjpHQkmdfq1i1jgwUgu/638EKzBfLcnRYX8Rn
DO9CWnHcql/4hp226fIWZN/SyReE81n7UkLDMAglhHgiezHMSH1GYVu4IlfpLVXn
brLVo83KioH5MPFWmZv5tigpU/G8dTx9yVGv1//YW2qqRYYqeIKJfapBaY/bNqyD
vYRfZo1K2brtHx4bToY6mALRF4ruV5SVZGS69e4Sh692C2pXSVbCpRhQ/2WnvkZH
leFIdmNmQN61MC1k26A620Rm+pAsXX71dln0u96xbrCgEVbi6ccfXzbFKtVmThVB
w11CLvVTviOm99TmcgpmDS4cf08AEQEAAYkBHwQYAQIACQUCVD1UOgIbDAAKCRDQ
TbLkkB+8pR+fB/0SeTcRr1duN7VYWdtng1+jO0ornIBtUraglN01dEEmiwN83DTi
J37i+nll+4is7BtiXqhumRptKh1v8UUMyFX/rjjoojCJBg5NExsiOYl3O4le68oF
3+XC+n7yrlyNmI15+3dcQmC9F6HN8EBZgrn5YPKGIOMHTGatB5PryMKg2IKiN5GZ
E0hmrOQgmcGrkeqysKACQYUHTasSk2IY1l1G5YQglqCaBh4+UC82Dmg5fTBbHjxP
YhhojkP4aD/0YW7dgql3nzYqvPCAjBH1Cf6rA9HvAJwUP9Ig/okcrrPEKm638+mG
+vNIuLqIkA4oFLBAAIrgMiQZ+NZz9uD6DJE7
=FO7G
-----END PGP PUBLIC KEY BLOCK-----
"""

# key A1885A7C: public key "Leap Test Key <leap@leap.se>"
EXPIRED_FINGERPRINT = "7C1F68B0E14157B09B5F4ADE6F15F004A1885A7C"
EXPIRED_KEY = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

mQENBBvrfd0BCADGNpspaNhsbhSjKioCWrE2MTTYC+Sdpes22RabdhQyOCWvlSbj
b8p0y3kmnMOtVBT+c22/w7eu2YBfIpS4RswgE5ypr/1kZLFQueVe/cp29GjPvLwJ
82A3EOHcmXs8rSJ76h2bnkySvbJawz9rwCcaXhpdAwC+sjWvbqiwZYEL+90I4Xp3
acDh9vNtPxDCg5RdI0bfdIEBGgHTfsda3kWGvo1wH5SgrTRq0+EcTI7aJgkMmM/A
IhnpACE52NvGdG9eB3x7xyQFsQqK8F0XvEev2UJH4SR7vb+Z7FNTJKCy6likYbSV
wGGFuowFSESnzXuUI6PcjyuO6FUbMgeM5euFABEBAAG0HExlYXAgVGVzdCBLZXkg
PGxlYXBAbGVhcC5zZT6JAT4EEwECACgFAhvrfd0CGwMFCQABUYAGCwkIBwMCBhUI
AgkKCwQWAgMBAh4BAheAAAoJEG8V8AShiFp8VNkH/iCQcXkTfMOVlL2rQRyZtJEO
Lr5uTyyY8O6ubeNCHqZzlIopiPAsv4hIYjjMDvOfZ9R53YgmbacUm0rvh1B4MSUf
k+sa9/tequ3y44LUKp7AB6NyyLgVOU5ngl2w+bi7CgXAep3oP4joYKcU0mmSAc2S
2Gj85DVqP0kdzNs47esvyj7g1TOfdBwmLsTx/219H+w3dNBeyCQWkYCYNh7MX/Ba
SZ+P0xr4FetcOVPM3wAzUtDG7hKsgccoIXt0FWhG/nn8cETfGH+o3W/ky7Jktatx
DGDHoZJvAaG2B2ey1pAQlezr8p/O+ZVABiigHk1S+myBHyhlXzUcjhQnEG7aHZ65
AQ0EG+t93QEIAKqRq/2sBDW4g3FU+11LhixT+GosrfVvnitz3S9k2tBXok/wYpI1
XeA+kTHiF0LaqoaciDRvkA9DvhDbSrNM1yeuYRyZiHlTmoPZ/Fkl60oA2cyLd1L5
sXbuipY3TEiakugdSU4rzgi0hFycm6Go6yq2G6eC6UALvD9CTMdZHw40TadG9xpm
4thYPuJ1kPH8/bkbTi9sLHoApYgL+7ssje8w4epr0qD4IGxeKwJPf/tbTRpnd8w3
leldixHHKAutNt49p0pkXlORAHRpUmp+KMZhFvCvIPwe9o5mYtMR7sDRxjY61ZEQ
KLyKoh5wsJsaPXBjdG7cf6G/cBcwvnQVUHcAEQEAAYkBJQQYAQIADwUCG+t93QIb
DAUJAAFRgAAKCRBvFfAEoYhafOPgB/9z4YCyT/N0262HtegHykhsyykuqEeNb1LV
D9INcP+RbCX/0IjFgP4DTMPP7qqF1OBwR276maALT321Gqxc5HN5YrwxGdmoyBLm
unaQJJlD+7B1C+jnO6r4m44obvJ/NMERxVyzkXap3J2VgRIO1wNLI9I0sH6Kj5/j
Mgy06OwXDcqIc+jB4sIJ3Tnm8LZ3phJzNEm9mI8Ak0oJ7IEcMndR6DzmRt1rJQcq
K/D7hOG02zvyRhxF27U1qR1MxeU/gNnOx8q4dnVyWB+EiV1sFl4iTOyYHEsoyd7W
Osuse7+NkyUHgMXMVW7cz+nU7iO+ht2rkBtv+Z5LGlzgHTeFjKci
=WhX+
-----END PGP PUBLIC KEY BLOCK-----
"""
# updated expiration date
EXPIRED_KEY_NEW_EXPIRY_DATE = datetime.fromtimestamp(2045319180)
EXPIRED_KEY_UPDATED = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

mQENBBvrfd0BCADGNpspaNhsbhSjKioCWrE2MTTYC+Sdpes22RabdhQyOCWvlSbj
b8p0y3kmnMOtVBT+c22/w7eu2YBfIpS4RswgE5ypr/1kZLFQueVe/cp29GjPvLwJ
82A3EOHcmXs8rSJ76h2bnkySvbJawz9rwCcaXhpdAwC+sjWvbqiwZYEL+90I4Xp3
acDh9vNtPxDCg5RdI0bfdIEBGgHTfsda3kWGvo1wH5SgrTRq0+EcTI7aJgkMmM/A
IhnpACE52NvGdG9eB3x7xyQFsQqK8F0XvEev2UJH4SR7vb+Z7FNTJKCy6likYbSV
wGGFuowFSESnzXuUI6PcjyuO6FUbMgeM5euFABEBAAG0HExlYXAgVGVzdCBLZXkg
PGxlYXBAbGVhcC5zZT6JAT4EEwECACgCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B
AheABQJUURIXBQld/ZovAAoJEG8V8AShiFp8xUcIALcAHZbaxvyhHRGOrwDddbH0
fFDK0AqKTsIT7y4D/HLFCP5zG3Ck7qGPZdkHXZfzq8rIb+zUjW3oJIVI1IucHxG2
T5kppa8RFCBAFlRWYf6R3isX3YL0d3QSragjoxRNPcHNU8ALHcvfSonFHBoi4fH4
4rvgksAiT68SsdPaoXDlabx5T15evu/7T5e/DGMQVPMxiaSuSQhbOKuMk2wcFdmL
tBYHLZPa54hHPNhEDyxLgtKKph0gObk9ojKfH9kPvLveIcpS5CqTJfN/kqBz7CJW
wEeAi2iG3H1OEB25aCUdTxXSRNlGqEgcWPaWxtc1RzlARu7LB64OUZuRy4puiAG5
AQ0EG+t93QEIAKqRq/2sBDW4g3FU+11LhixT+GosrfVvnitz3S9k2tBXok/wYpI1
XeA+kTHiF0LaqoaciDRvkA9DvhDbSrNM1yeuYRyZiHlTmoPZ/Fkl60oA2cyLd1L5
sXbuipY3TEiakugdSU4rzgi0hFycm6Go6yq2G6eC6UALvD9CTMdZHw40TadG9xpm
4thYPuJ1kPH8/bkbTi9sLHoApYgL+7ssje8w4epr0qD4IGxeKwJPf/tbTRpnd8w3
leldixHHKAutNt49p0pkXlORAHRpUmp+KMZhFvCvIPwe9o5mYtMR7sDRxjY61ZEQ
KLyKoh5wsJsaPXBjdG7cf6G/cBcwvnQVUHcAEQEAAYkBJQQYAQIADwUCG+t93QIb
DAUJAAFRgAAKCRBvFfAEoYhafOPgB/9z4YCyT/N0262HtegHykhsyykuqEeNb1LV
D9INcP+RbCX/0IjFgP4DTMPP7qqF1OBwR276maALT321Gqxc5HN5YrwxGdmoyBLm
unaQJJlD+7B1C+jnO6r4m44obvJ/NMERxVyzkXap3J2VgRIO1wNLI9I0sH6Kj5/j
Mgy06OwXDcqIc+jB4sIJ3Tnm8LZ3phJzNEm9mI8Ak0oJ7IEcMndR6DzmRt1rJQcq
K/D7hOG02zvyRhxF27U1qR1MxeU/gNnOx8q4dnVyWB+EiV1sFl4iTOyYHEsoyd7W
Osuse7+NkyUHgMXMVW7cz+nU7iO+ht2rkBtv+Z5LGlzgHTeFjKci
=79Ll
-----END PGP PUBLIC KEY BLOCK-----
"""


import unittest
if __name__ == "__main__":
    unittest.main()
