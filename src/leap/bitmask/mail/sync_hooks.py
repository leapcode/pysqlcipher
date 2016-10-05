# -*- coding: utf-8 -*-
# sync_hooks.py
# Copyright (C) 2015 LEAP
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
Soledad PostSync Hooks.

Process every new document of interest after every soledad synchronization,
using the hooks that soledad exposes via plugins.
"""
from re import compile as regex_compile

from zope.interface import implements
from twisted.internet import defer
from twisted.plugin import IPlugin
from twisted.logger import Logger

from leap.bitmask.mail import constants
from leap.soledad.client.interfaces import ISoledadPostSyncPlugin

logger = Logger()


def _get_doc_type_preffix(s):
    return s[:2]


class MailProcessingPostSyncHook(object):
    implements(IPlugin, ISoledadPostSyncPlugin)

    META_DOC_PREFFIX = _get_doc_type_preffix(constants.METAMSGID)
    watched_doc_types = (META_DOC_PREFFIX, )

    _account = None
    _pending_docs = []
    _processing_deferreds = []

    def process_received_docs(self, doc_id_list):
        if self._has_configured_account():
            process_fun = self._make_uid_index
        else:
            self._processing_deferreds = []
            process_fun = self._queue_doc_id

        for doc_id in doc_id_list:
            if _get_doc_type_preffix(doc_id) in self.watched_doc_types:
                logger.info("Mail post-sync hook: processing %s" % doc_id)
                process_fun(doc_id)

        return defer.gatherResults(self._processing_deferreds)

    def set_account(self, account):
        self._account = account
        if account:
            self._process_queued_docs()

    def _has_configured_account(self):
        return self._account is not None

    def _queue_doc_id(self, doc_id):
        self._pending_docs.append(doc_id)

    def _make_uid_index(self, mdoc_id):
        indexer = self._account.mbox_indexer
        mbox_uuid = _get_mbox_uuid(mdoc_id)
        if mbox_uuid:
            chash = _get_chash_from_mdoc(mdoc_id)
            logger.debug('making index table for %s:%s' % (mbox_uuid, chash))
            index_docid = constants.METAMSGID.format(
                mbox_uuid=mbox_uuid.replace('-', '_'),
                chash=chash)
            # XXX could avoid creating table if I track which ones I already
            # have seen -- but make sure *it's already created* before
            # inserting the index entry!.
            d = indexer.create_table(mbox_uuid)
            d.addBoth(lambda _: indexer.insert_doc(mbox_uuid, index_docid))
            self._processing_deferreds.append(d)

    def _process_queued_docs(self):
        assert(self._has_configured_account())
        pending = self._pending_docs
        logger.info("Mail post-sync hook: processing queued docs")

        def remove_pending_docs(res):
            self._pending_docs = []
            return res

        d = self.process_received_docs(pending)
        d.addCallback(remove_pending_docs)
        return d


_mbox_uuid_regex = regex_compile(constants.METAMSGID_MBOX_RE)
_mdoc_chash_regex = regex_compile(constants.METAMSGID_CHASH_RE)


def _get_mbox_uuid(doc_id):
    matches = _mbox_uuid_regex.findall(doc_id)
    if matches:
        return matches[0].replace('_', '-')


def _get_chash_from_mdoc(doc_id):
    matches = _mdoc_chash_regex.findall(doc_id)
    if matches:
        return matches[0]
