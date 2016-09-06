# -*- coding: utf-8 -*-
# test_opengpg_speed.py
# Copyright (C) 2016 LEAP Encryption Acess Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Benchmarking for the leap.bitmask.keymanager.openpgp module
"""

import commands
import pytest

from functools import partial

from gnupg import GPG
from leap.bitmask.keymanager.wrapper import TempGPGWrapper

from common import CIPHERTEXT
from common import SIGNEDTEXT


GROUP_INIT = 'initialization only'
GROUP_CRYPTO = 'crypto only'
GROUP_INIT_AND_CRYPTO = 'initialization and crypto'


# the gnupg module gets the binary version each time the GPG object is
# initialized. In some platforms this takes hundreds of milliseconds, and
# sometimes more than a second. This is currently a known bug. For making it
# evident, we provide a way to bypass the version check by monkeypatching the
# actual function that does the job.

def get_gpg_version():
    output = commands.getoutput(
        'gpg --list-config --with-colons | grep version')
    version = output.split(':').pop()
    return version


GPG_VERSION = get_gpg_version()


def mock_gpg_get_version(monkeypatch):
    def _setver(self):
        self.binary_version = GPG_VERSION
    monkeypatch.setattr(
        GPG, '_check_sane_and_get_gpg_version', _setver)


#
# generic speed test creator
#

def create_test(fun, num_keys=0, mock_get_version=True, init=None, group=None):

    @pytest.mark.benchmark(group=group)
    def test(tmpdir, benchmark, openpgp_keys, monkeypatch):

        if mock_get_version:
            mock_gpg_get_version(monkeypatch)

        if init:
            res = init(tmpdir, benchmark, openpgp_keys, monkeypatch, num_keys)
            benchmark(fun, res)
        else:
            benchmark(
                fun, tmpdir, benchmark, openpgp_keys, monkeypatch, num_keys)

    return test


#
# gpg initializarion: 0, 1 and 2 keys
#

def gpg_init_only(tmpdir, benchmark, openpgp_keys, monkeypatch, num_keys):
    keys = openpgp_keys[0:num_keys]
    gpg = GPG(homedir=tmpdir.dirname)
    for key in keys:
        gpg.import_keys(key.key_data)


test_gpg_init_nokey_slow = create_test(
    gpg_init_only, num_keys=0,
    mock_get_version=False,
    group=GROUP_INIT)
test_gpg_init_1key_slow = create_test(
    gpg_init_only, num_keys=1,
    mock_get_version=False,
    group=GROUP_INIT)
test_gpg_init_2keys_slow = create_test(
    gpg_init_only, num_keys=2,
    mock_get_version=False,
    group=GROUP_INIT)

test_gpg_init_nokey = create_test(
    gpg_init_only, num_keys=0,
    group=GROUP_INIT)
test_gpg_init_1key = create_test(
    gpg_init_only, num_keys=1,
    group=GROUP_INIT)
test_gpg_init_2keys = create_test(
    gpg_init_only, num_keys=2,
    group=GROUP_INIT)


#
# wrapper initialization: 0, 1 and 2 keys
#

def wrapper_init_only(tmpdir, benchmark, openpgp_keys, monkeypatch, num_keys):
    keys = openpgp_keys[0:num_keys]
    wrapper = TempGPGWrapper(keys=keys)
    with wrapper as gpg:
        assert GPG == type(gpg)


test_wrapper_init_nokey_slow = create_test(
    wrapper_init_only, num_keys=0,
    mock_get_version=False,
    group=GROUP_INIT)
test_wrapper_init_1key_slow = create_test(
    wrapper_init_only, num_keys=1,
    mock_get_version=False,
    group=GROUP_INIT)
test_wrapper_init_2keys_slow = create_test(
    wrapper_init_only, num_keys=2,
    mock_get_version=False,
    group=GROUP_INIT)

test_wrapper_init_nokey = create_test(
    wrapper_init_only, num_keys=0,
    group=GROUP_INIT)
test_wrapper_init_1key = create_test(
    wrapper_init_only, num_keys=1,
    group=GROUP_INIT)
test_wrapper_init_2keys = create_test(
    wrapper_init_only, num_keys=2,
    group=GROUP_INIT)


#
# initialization + encryption
#

PLAINTEXT = ' ' * 10000  # 10 KB


def gpg_init_exec(fun, tmpdir, benchmark, openpgp_keys, monkeypatch, _):
    pubkey = openpgp_keys[0]
    privkey = openpgp_keys[2]  # this is PRIVATE_KEY
    gpg = GPG(homedir=tmpdir.dirname)
    gpg.import_keys(pubkey.key_data)
    gpg.import_keys(privkey.key_data)
    fun((gpg, pubkey, privkey))


def wrapper_init_exec(fun, tmpdir, benchmark, openpgp_keys, monkeypatch, _):
    pubkey = openpgp_keys[0]
    privkey = openpgp_keys[2]
    wrapper = TempGPGWrapper(keys=[pubkey, privkey])
    wrapper._build_keyring()
    fun((wrapper._gpg, pubkey, privkey))


def gpg_enc(res):
    gpg, pubkey, _ = res
    ciphertext = gpg.encrypt(PLAINTEXT, pubkey.fingerprint)
    assert ciphertext.ok
    assert len(ciphertext.data)


test_gpg_init_enc = create_test(
    partial(gpg_init_exec, gpg_enc),
    group=GROUP_INIT_AND_CRYPTO)
test_wrapper_init_enc = create_test(
    partial(wrapper_init_exec, gpg_enc),
    group=GROUP_INIT_AND_CRYPTO)


#
# initialization + decryption
#

def gpg_dec(res):
    gpg, _, _ = res
    plaintext = gpg.decrypt(CIPHERTEXT)
    assert plaintext.ok
    assert len(plaintext.data)


test_gpg_init_dec = create_test(
    partial(gpg_init_exec, gpg_dec),
    group=GROUP_INIT_AND_CRYPTO)
test_wrapper_init_dec = create_test(
    partial(wrapper_init_exec, gpg_dec),
    group=GROUP_INIT_AND_CRYPTO)


#
# initialization + sign
#

def gpg_sign(res):
    gpg, _, privkey = res
    gpg.import_keys(privkey.key_data)
    signed = gpg.sign(PLAINTEXT, default_key=privkey.fingerprint)
    assert signed.status == 'begin signing'
    assert len(signed.data) > len(PLAINTEXT)
    assert '-----BEGIN PGP SIGNATURE-----' in signed.data
    assert '-----END PGP SIGNATURE-----' in signed.data


test_gpg_init_sign = create_test(
    partial(gpg_init_exec, gpg_sign),
    group=GROUP_INIT_AND_CRYPTO)
test_wrapper_init_sign = create_test(
    partial(wrapper_init_exec, gpg_sign),
    group=GROUP_INIT_AND_CRYPTO)


#
# initialization + verify
#

def gpg_verify(res):
    gpg, _, privkey = res
    signed = gpg.verify(SIGNEDTEXT)
    assert signed.valid


test_gpg_init_verify = create_test(
    partial(gpg_init_exec, gpg_verify),
    group=GROUP_INIT_AND_CRYPTO)
test_wrapper_init_verify = create_test(
    partial(wrapper_init_exec, gpg_verify),
    group=GROUP_INIT_AND_CRYPTO)


#
# encryption only
#

def gpg_init(tmpdir, benchmark, openpgp_keys, monkeypatch, _):
    pubkey = openpgp_keys[0]
    privkey = openpgp_keys[2]  # this is PRIVATE_KEY
    gpg = GPG(homedir=tmpdir.dirname)
    gpg.import_keys(pubkey.key_data)
    gpg.import_keys(privkey.key_data)
    return gpg, pubkey, privkey


def wrapper_init(tmpdir, benchmark, openpgp_keys, monkeypatch, _):
    pubkey = openpgp_keys[0]
    privkey = openpgp_keys[2]
    wrapper = TempGPGWrapper(keys=[pubkey, privkey])
    wrapper._build_keyring()
    return wrapper._gpg, pubkey, privkey


test_gpg_enc = create_test(
    gpg_enc, init=gpg_init, group=GROUP_CRYPTO)
test_wrapper_enc = create_test(
    gpg_enc, init=wrapper_init, group=GROUP_CRYPTO)


#
# decryption only
#

test_gpg_dec = create_test(
    gpg_dec,
    init=gpg_init, group=GROUP_CRYPTO)
test_wrapper_dec = create_test(
    gpg_dec,
    init=wrapper_init, group=GROUP_CRYPTO)


#
# sign only
#

test_gpg_sign = create_test(
    gpg_sign, init=gpg_init, group=GROUP_CRYPTO)
test_wrapper_sign = create_test(
    gpg_sign, init=wrapper_init, group=GROUP_CRYPTO)


#
# verify only
#

test_gpg_verify = create_test(
    gpg_verify, init=gpg_init, group=GROUP_CRYPTO)
test_wrapper_verify = create_test(
    gpg_verify, init=wrapper_init, group=GROUP_CRYPTO)
