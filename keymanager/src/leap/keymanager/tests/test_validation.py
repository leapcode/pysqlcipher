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

import unittest
from datetime import datetime
from twisted.internet.defer import inlineCallbacks

from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import (
    KeyNotValidUpgrade
)
from leap.keymanager.tests import (
    KeyManagerWithSoledadTestCase,
    ADDRESS,
    PUBLIC_KEY,
    ADDRESS_2,
    PUBLIC_KEY_2,
    PRIVATE_KEY_2,
    KEY_FINGERPRINT
)
from leap.keymanager.validation import ValidationLevels


class ValidationLevelsTestCase(KeyManagerWithSoledadTestCase):

    @inlineCallbacks
    def test_none_old_key(self):
        km = self._key_manager()
        yield km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, KEY_FINGERPRINT)

    @inlineCallbacks
    def test_cant_upgrade(self):
        km = self._key_manager()
        yield km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS,
                             validation=ValidationLevels.Provider_Trust)
        d = km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS)
        yield self.assertFailure(d, KeyNotValidUpgrade)

    @inlineCallbacks
    def test_fingerprint_level(self):
        km = self._key_manager()
        yield km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        yield km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS,
                             validation=ValidationLevels.Fingerprint)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, UNRELATED_FINGERPRINT)

    @inlineCallbacks
    def test_expired_key(self):
        km = self._key_manager()
        yield km.put_raw_key(EXPIRED_KEY, OpenPGPKey, ADDRESS)
        yield km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, UNRELATED_FINGERPRINT)

    @inlineCallbacks
    def test_expired_fail_lower_level(self):
        km = self._key_manager()
        yield km.put_raw_key(
            EXPIRED_KEY, OpenPGPKey, ADDRESS,
            validation=ValidationLevels.Third_Party_Endorsement)
        d = km.put_raw_key(
            UNRELATED_KEY,
            OpenPGPKey,
            ADDRESS,
            validation=ValidationLevels.Provider_Trust)
        yield self.assertFailure(d, KeyNotValidUpgrade)

    @inlineCallbacks
    def test_roll_back(self):
        km = self._key_manager()
        yield km.put_raw_key(EXPIRED_KEY_UPDATED, OpenPGPKey, ADDRESS)
        yield km.put_raw_key(EXPIRED_KEY, OpenPGPKey, ADDRESS)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.expiry_date, EXPIRED_KEY_NEW_EXPIRY_DATE)

    @inlineCallbacks
    def test_not_used(self):
        km = self._key_manager()
        yield km.put_raw_key(UNEXPIRED_KEY, OpenPGPKey, ADDRESS,
                             validation=ValidationLevels.Provider_Trust)
        yield km.put_raw_key(UNRELATED_KEY, OpenPGPKey, ADDRESS,
                             validation=ValidationLevels.Provider_Endorsement)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, UNRELATED_FINGERPRINT)

    @inlineCallbacks
    def test_used_with_verify(self):
        TEXT = "some text"

        km = self._key_manager()
        yield km.put_raw_key(UNEXPIRED_KEY, OpenPGPKey, ADDRESS)
        yield km.encrypt(TEXT, ADDRESS, OpenPGPKey)

        km2 = self._key_manager()
        yield km2.put_raw_key(UNEXPIRED_PRIVATE, OpenPGPKey, ADDRESS)
        signature = yield km2.sign(TEXT, ADDRESS, OpenPGPKey)

        yield km.verify(TEXT, ADDRESS, OpenPGPKey, detached_sig=signature)
        d = km.put_raw_key(
            UNRELATED_KEY, OpenPGPKey, ADDRESS,
            validation=ValidationLevels.Provider_Endorsement)
        yield self.assertFailure(d, KeyNotValidUpgrade)

    @inlineCallbacks
    def test_used_with_decrypt(self):
        TEXT = "some text"

        km = self._key_manager()
        yield km.put_raw_key(UNEXPIRED_KEY, OpenPGPKey, ADDRESS)
        yield km.put_raw_key(PRIVATE_KEY_2, OpenPGPKey, ADDRESS_2)
        yield km.encrypt(TEXT, ADDRESS, OpenPGPKey)

        km2 = self._key_manager()
        yield km2.put_raw_key(UNEXPIRED_PRIVATE, OpenPGPKey, ADDRESS)
        yield km2.put_raw_key(PUBLIC_KEY_2, OpenPGPKey, ADDRESS_2)
        encrypted = yield km2.encrypt(TEXT, ADDRESS_2, OpenPGPKey,
                                      sign=ADDRESS)

        yield km.decrypt(encrypted, ADDRESS_2, OpenPGPKey, verify=ADDRESS)
        d = km.put_raw_key(
            UNRELATED_KEY, OpenPGPKey, ADDRESS,
            validation=ValidationLevels.Provider_Endorsement)
        yield self.assertFailure(d, KeyNotValidUpgrade)

    @inlineCallbacks
    def test_signed_key(self):
        km = self._key_manager()
        yield km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        yield km.put_raw_key(SIGNED_KEY, OpenPGPKey, ADDRESS)
        key = yield km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        self.assertEqual(key.fingerprint, SIGNED_FINGERPRINT)


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
EXPIRED_KEY_NEW_EXPIRY_DATE = datetime.fromtimestamp(2049717872)
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
AheABQJUlDCSBQleQLiTAAoJEG8V8AShiFp8t3QH/1eqkVIScXmqaCVeno3VSKiH
HqnxiHcEgtpNRfUlP6tLD4H6QPEpvoUI9S/8HSYi3nbDGXEX8ycKlnwxjdIqWSOW
xj91/7uQAo+dP9QaVJ6xgaAiqzN1x3JzX3Js1wTodmNV0TfmGjxwnC5up/xK7/pd
KuDP3woDsRlwy8Lgj67mkn49xfAFHo6hI6SD36UBDAC/ELq6kZaba4Kk0fEVHCEz
HX0B09ZIY9fmf305cEB3dNh6SMQgKtH0wKozaqI2UM2B+cs3z08bC+YuUUh7UJTH
yr+hI7vF4/WEeJB3fuhP3xsumLhV8P47DaJ7oivmtsDEbAJFKqvigEqNES73Xpy5
AQ0EG+t93QEIAKqRq/2sBDW4g3FU+11LhixT+GosrfVvnitz3S9k2tBXok/wYpI1
XeA+kTHiF0LaqoaciDRvkA9DvhDbSrNM1yeuYRyZiHlTmoPZ/Fkl60oA2cyLd1L5
sXbuipY3TEiakugdSU4rzgi0hFycm6Go6yq2G6eC6UALvD9CTMdZHw40TadG9xpm
4thYPuJ1kPH8/bkbTi9sLHoApYgL+7ssje8w4epr0qD4IGxeKwJPf/tbTRpnd8w3
leldixHHKAutNt49p0pkXlORAHRpUmp+KMZhFvCvIPwe9o5mYtMR7sDRxjY61ZEQ
KLyKoh5wsJsaPXBjdG7cf6G/cBcwvnQVUHcAEQEAAYkBJQQYAQIADwIbDAUCVJQw
3QUJXkC4/QAKCRBvFfAEoYhafEtiB/9hMfSFNMxtlIJDJArG4JwR7sBOatYUT858
qZnTgGETZN8wXpeEpXWKdDdmCX9aeE9jsDNgSQ5WWpqU21bGMXh1IGjAzmqTqq3/
ik1vALuaVfr6OqjTzrJVQujT61CGed26xpP3Zh8hLKyKa+dXnX/VpgZS42wZLPx2
wcODfANmTfE2AhMap/RyDy21q4nau+z2hMEOKdtF8dpP+pEvzoN5ZexYP1hfT+Av
oFPyVB5YtEMfxTEshDKRPjbdgNmw4faKXd5Cbelo4YxxpO16FHb6gzIdjOX15vQ+
KwcVXzg9xk4D3cr1mnTCops/iv6TXvcw4Wbo70rrKXwkjl8LKjOP
=sHoe
-----END PGP PUBLIC KEY BLOCK-----
"""
UNEXPIRED_KEY = EXPIRED_KEY_UPDATED
UNEXPIRED_PRIVATE = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

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
=dZE8
-----END PGP PRIVATE KEY BLOCK-----
"""

# key CA1AD31E: public key "Leap Test Key <leap@leap.se>"
# signed by E36E738D69173C13D709E44F2F455E2824D18DDF
SIGNED_FINGERPRINT = "6704CF3362087DA23E3D2DF8ED81DFD1CA1AD31E"
SIGNED_KEY = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.12 (GNU/Linux)

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
=xprj
-----END PGP PUBLIC KEY BLOCK-----
"""

if __name__ == "__main__":
    import unittest
    unittest.main()
