# soledad.py
# Copyright (C) 2014 LEAP
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
Soledadad MailAdaptor module.
"""
import re
from collections import defaultdict
from email import message_from_string
from functools import partial

from pycryptopp.hash import sha256
from twisted.internet import defer
from zope.interface import implements

from leap.common.check import leap_assert, leap_assert_type

from leap.mail import constants
from leap.mail import walk
from leap.mail.adaptors import soledad_indexes as indexes
from leap.mail.constants import INBOX_NAME
from leap.mail.adaptors import models
from leap.mail.imap.mailbox import normalize_mailbox
from leap.mail.utils import lowerdict, first
from leap.mail.utils import stringify_parts_map
from leap.mail.interfaces import IMailAdaptor, IMessageWrapper


# TODO
# [ ] Convenience function to create mail specifying subject, date, etc?


_MSGID_PATTERN = r"""<([\w@.]+)>"""
_MSGID_RE = re.compile(_MSGID_PATTERN)


class DuplicatedDocumentError(Exception):
    """
    Raised when a duplicated document is detected.
    """
    pass


class SoledadDocumentWrapper(models.DocumentWrapper):
    """
    A Wrapper object that can be manipulated, passed around, and serialized in
    a format that the Soledad Store understands.

    It ensures atomicity of the document operations on creation, update and
    deletion.
    """
    # TODO we could also use a _dirty flag (in models)

    # We keep a dictionary with DeferredLocks, that will be
    # unique to every subclass of SoledadDocumentWrapper.
    _k_locks = defaultdict(defer.DeferredLock)

    @classmethod
    def _get_klass_lock(cls):
        """
        Get a DeferredLock that is unique for this subclass name.
        Used to lock the access to indexes in the `get_or_create` call
        for a particular DocumentWrapper.
        """
        return cls._k_locks[cls.__name__]

    def __init__(self, **kwargs):
        doc_id = kwargs.pop('doc_id', None)
        self._doc_id = doc_id
        self._future_doc_id = kwargs.pop('future_doc_id', None)
        self._lock = defer.DeferredLock()
        super(SoledadDocumentWrapper, self).__init__(**kwargs)

    @property
    def doc_id(self):
        return self._doc_id

    @property
    def future_doc_id(self):
        return self._future_doc_id

    def set_future_doc_id(self, doc_id):
        self._future_doc_id = doc_id

    def create(self, store):
        """
        Create the documents for this wrapper.
        Since this method will not check for duplication, the
        responsibility of avoiding duplicates is left to the caller.

        You might be interested in using `get_or_create` classmethod
        instead (that's the preferred way of creating documents from
        the wrapper object).

        :return: a deferred that will fire when the underlying
                 Soledad document has been created.
        :rtype: Deferred
        """
        leap_assert(self._doc_id is None,
                    "This document already has a doc_id!")

        def update_doc_id(doc):
            self._doc_id = doc.doc_id
            self._future_doc_id = None
            return doc

        if self.future_doc_id is None:
            d = store.create_doc(self.serialize())
        else:
            d = store.create_doc(self.serialize(),
                                 doc_id=self.future_doc_id)
        d.addCallback(update_doc_id)
        return d

    def update(self, store):
        """
        Update the documents for this wrapper.

        :return: a deferred that will fire when the underlying
                 Soledad document has been updated.
        :rtype: Deferred
        """
        # the deferred lock guards against revision conflicts
        return self._lock.run(self._update, store)

    def _update(self, store):
        leap_assert(self._doc_id is not None,
                    "Need to create doc before updating")

        def update_and_put_doc(doc):
            doc.content.update(self.serialize())
            return store.put_doc(doc)

        d = store.get_doc(self._doc_id)
        d.addCallback(update_and_put_doc)
        return d

    def delete(self, store):
        """
        Delete the documents for this wrapper.

        :return: a deferred that will fire when the underlying
                 Soledad document has been deleted.
        :rtype: Deferred
        """
        # the deferred lock guards against conflicts while updating
        return self._lock.run(self._delete, store)

    def _delete(self, store):
        leap_assert(self._doc_id is not None,
                    "Need to create doc before deleting")
        # XXX might want to flag this DocumentWrapper to avoid
        # updating it by mistake. This could go in models.DocumentWrapper

        def delete_doc(doc):
            return store.delete_doc(doc)

        d = store.get_doc(self._doc_id)
        d.addCallback(delete_doc)
        return d

    @classmethod
    def get_or_create(cls, store, index, value):
        """
        Get a unique DocumentWrapper by index, or create a new one if the
        matching query does not exist.

        :param index: the primary index for the model.
        :type index: str
        :param value: the value to query the primary index.
        :type value: str

        :return: a deferred that will be fired with the SoledadDocumentWrapper
                 matching the index query, either existing or just created.
        :rtype: Deferred
        """
        return cls._get_klass_lock().run(
            cls._get_or_create, store, index, value)

    @classmethod
    def _get_or_create(cls, store, index, value):
        assert store is not None
        assert index is not None
        assert value is not None

        def get_main_index():
            try:
                return cls.model.__meta__.index
            except AttributeError:
                raise RuntimeError("The model is badly defined")

        def try_to_get_doc_from_index(indexes):
            values = []
            idx_def = dict(indexes)[index]
            if len(idx_def) == 1:
                values = [value]
            else:
                main_index = get_main_index()
                fields = cls.model.serialize()
                for field in idx_def:
                    if field == main_index:
                        values.append(value)
                    else:
                        values.append(fields[field])
            d = store.get_from_index(index, *values)
            return d

        def get_first_doc_if_any(docs):
            if not docs:
                return None
            if len(docs) > 1:
                raise DuplicatedDocumentError
            return docs[0]

        def wrap_existing_or_create_new(doc):
            if doc:
                return cls(doc_id=doc.doc_id, **doc.content)
            else:
                return create_and_wrap_new_doc()

        def create_and_wrap_new_doc():
            # XXX use closure to store indexes instead of
            # querying for them again.
            d = store.list_indexes()
            d.addCallback(get_wrapper_instance_from_index)
            d.addCallback(return_wrapper_when_created)
            return d

        def get_wrapper_instance_from_index(indexes):
            init_values = {}
            idx_def = dict(indexes)[index]
            if len(idx_def) == 1:
                init_value = {idx_def[0]: value}
                return cls(**init_value)
            main_index = get_main_index()
            fields = cls.model.serialize()
            for field in idx_def:
                if field == main_index:
                    init_values[field] = value
                else:
                    init_values[field] = fields[field]
            return cls(**init_values)

        def return_wrapper_when_created(wrapper):
            d = wrapper.create(store)
            d.addCallback(lambda doc: wrapper)
            return d

        d = store.list_indexes()
        d.addCallback(try_to_get_doc_from_index)
        d.addCallback(get_first_doc_if_any)
        d.addCallback(wrap_existing_or_create_new)
        return d

    @classmethod
    def get_all(cls, store):
        """
        Get a collection of wrappers around all the documents belonging
        to this kind.

        For this to work, the model.__meta__ needs to include a tuple with
        the index to be used for listing purposes, and which is the field to be
        used to query the index.

        Note that this method only supports indexes of a single field at the
        moment. It also might be too expensive to return all the documents
        matching the query, so handle with care.

        class __meta__(object):
            index = "name"
            list_index = ("by-type", "type_")

        :return: a deferred that will be fired with an iterable containing
                 as many SoledadDocumentWrapper are matching the index defined
                 in the model as the `list_index`.
        :rtype: Deferred
        """
        # TODO
        # [ ] extend support to indexes with n-ples
        # [ ] benchmark the cost of querying and returning indexes in a big
        #     database. This might badly need pagination before being put to
        #     serious use.
        return cls._get_klass_lock().run(cls._get_all, store)

    @classmethod
    def _get_all(cls, store):
        try:
            list_index, list_attr = cls.model.__meta__.list_index
        except AttributeError:
            raise RuntimeError("The model is badly defined: no list_index")
        try:
            index_value = getattr(cls.model, list_attr)
        except AttributeError:
            raise RuntimeError("The model is badly defined: "
                               "no attribute matching list_index")

        def wrap_docs(docs):
            return (cls(doc_id=doc.doc_id, **doc.content) for doc in docs)

        d = store.get_from_index(list_index, index_value)
        d.addCallback(wrap_docs)
        return d

    # TODO
    # [ ] get_count() ???

    def __repr__(self):
        try:
            idx = getattr(self, self.model.__meta__.index)
        except AttributeError:
            idx = ""
        return "<%s: %s (%s)>" % (self.__class__.__name__,
                                  idx, self._doc_id)


#
# Message documents
#

class FlagsDocWrapper(SoledadDocumentWrapper):

    class model(models.SerializableModel):
        type_ = "flags"
        chash = ""

        mbox = "inbox"
        seen = False
        deleted = False
        recent = False
        multi = False
        flags = []
        tags = []
        size = 0

        class __meta__(object):
            index = "mbox"

    def set_mbox(self, mbox):
        # XXX raise error if already created, should use copy instead
        new_id = constants.FDOCID.format(mbox=mbox, chash=self.chash)
        self._future_doc_id = new_id
        self.mbox = mbox


class HeaderDocWrapper(SoledadDocumentWrapper):

    class model(models.SerializableModel):
        type_ = "head"
        chash = ""

        date = ""
        subject = ""
        headers = {}
        part_map = {}
        body = ""  # link to phash of body
        msgid = ""
        multi = False

        class __meta__(object):
            index = "chash"


class ContentDocWrapper(SoledadDocumentWrapper):

    class model(models.SerializableModel):
        type_ = "cnt"
        phash = ""

        ctype = ""  # XXX index by ctype too?
        lkf = []  # XXX not implemented yet!
        raw = ""

        content_disposition = ""
        content_transfer_encoding = ""
        content_type = ""

        class __meta__(object):
            index = "phash"


class MetaMsgDocWrapper(SoledadDocumentWrapper):

    class model(models.SerializableModel):
        type_ = "meta"
        fdoc = ""
        hdoc = ""
        cdocs = []

    def set_mbox(self, mbox):
        # XXX raise error if already created, should use copy instead
        chash = re.findall(constants.FDOCID_CHASH_RE, self.fdoc)[0]
        new_id = constants.METAMSGID.format(mbox=mbox, chash=chash)
        new_fdoc_id = constants.FDOCID.format(mbox=mbox, chash=chash)
        self._future_doc_id = new_id
        self.fdoc = new_fdoc_id


class MessageWrapper(object):

    # TODO generalize wrapper composition?
    # This could benefit of a DeferredLock to create/update all the
    # documents at the same time maybe, and defend against concurrent updates?

    implements(IMessageWrapper)

    def __init__(self, mdoc, fdoc, hdoc, cdocs=None):
        """
        Need at least a metamsg-document, a flag-document and a header-document
        to instantiate a MessageWrapper. Content-documents can be retrieved
        lazily.

        cdocs, if any, should be a dictionary in which the keys are ascending
        integers, beginning at one, and the values are dictionaries with the
        content of the content-docs.
        """
        self.mdoc = MetaMsgDocWrapper(**mdoc)

        self.fdoc = FlagsDocWrapper(**fdoc)
        self.fdoc.set_future_doc_id(self.mdoc.fdoc)

        self.hdoc = HeaderDocWrapper(**hdoc)
        self.hdoc.set_future_doc_id(self.mdoc.hdoc)

        if cdocs is None:
            cdocs = {}
        cdocs_keys = cdocs.keys()
        assert sorted(cdocs_keys) == range(1, len(cdocs_keys) + 1)
        self.cdocs = dict([(key, ContentDocWrapper(**doc)) for (key, doc) in
                           cdocs.items()])
        for doc_id, cdoc in zip(self.mdoc.cdocs, self.cdocs.values()):
            cdoc.set_future_doc_id(doc_id)

    def create(self, store):
        """
        Create all the parts for this message in the store.
        """
        leap_assert(self.cdocs,
                    "Need non empty cdocs to create the "
                    "MessageWrapper documents")
        leap_assert(self.mdoc.doc_id is None,
                    "Cannot create: mdoc has a doc_id")
        leap_assert(self.fdoc.doc_id is None,
                    "Cannot create: fdoc has a doc_id")

        # TODO check that the doc_ids in the mdoc are coherent
        # TODO I think we need to tolerate the no hdoc.doc_id case, for when we
        # are doing a copy to another mailbox.
        # leap_assert(self.hdoc.doc_id is None,
        # "Cannot create: hdoc has a doc_id")
        d = []
        d.append(self.mdoc.create(store))
        d.append(self.fdoc.create(store))
        if self.hdoc.doc_id is None:
            d.append(self.hdoc.create(store))
        for cdoc in self.cdocs.values():
            if cdoc.doc_id is not None:
                # we could be just linking to an existing
                # content-doc.
                continue
            d.append(cdoc.create(store))
        return defer.gatherResults(d)

    def update(self, store):
        """
        Update the only mutable parts, which are within the flags document.
        """
        return self.fdoc.update(store)

    def delete(self, store):
        # Eventually this would have to do the duplicate search or send for the
        # garbage collector. At least the fdoc can be unlinked.
        raise NotImplementedError()

    def copy(self, store, newmailbox):
        """
        Return a copy of this MessageWrapper in a new mailbox.
        """
        # 1. copy the fdoc, mdoc
        # 2. remove the doc_id of that fdoc
        # 3. create it (with new doc_id)
        # 4. return new wrapper (new meta too!)
        raise NotImplementedError()

    def set_mbox(self, mbox):
        """
        Set the mailbox for this wrapper.
        This method should only be used before the Documents for the
        MessageWrapper have been created, will raise otherwise.
        """
        self.mdoc.set_mbox(mbox)
        self.fdoc.set_mbox(mbox)

#
# Mailboxes
#


class MailboxWrapper(SoledadDocumentWrapper):

    class model(models.SerializableModel):
        type_ = "mbox"
        mbox = INBOX_NAME
        flags = []
        closed = False
        subscribed = False
        rw = True

        class __meta__(object):
            index = "mbox"
            list_index = (indexes.TYPE_IDX, 'type_')


#
# Soledad Adaptor
#

# TODO make this an interface?
class SoledadIndexMixin(object):
    """
    this will need a class attribute `indexes`, that is a dictionary containing
    the index definitions for the underlying u1db store underlying soledad.

    It needs to be in the following format:
    {'index-name': ['field1', 'field2']}
    """
    # TODO could have a wrapper class for indexes, supporting introspection
    # and __getattr__
    indexes = {}

    store_ready = False
    _index_creation_deferreds = []

    # TODO we might want to move this logic to soledad itself
    # so that each application can pass a set of indexes for their data model.
    # TODO check also the decorator used in keymanager for waiting for indexes
    # to be ready.

    def initialize_store(self, store):
        """
        Initialize the indexes in the database.

        :param store: store
        :returns: a Deferred that will fire when the store is correctly
                  initialized.
        :rtype: deferred
        """
        # TODO I think we *should* get another deferredLock in here, but
        # global to the soledad namespace, to protect from several points
        # initializing soledad indexes at the same time.

        leap_assert(store, "Need a store")
        leap_assert_type(self.indexes, dict)
        self._index_creation_deferreds = []

        def _on_indexes_created(ignored):
            self.store_ready = True

        def _create_index(name, expression):
            d = store.create_index(name, *expression)
            self._index_creation_deferreds.append(d)

        def _create_indexes(db_indexes):
            db_indexes = dict(db_indexes)

            for name, expression in self.indexes.items():
                if name not in db_indexes:
                    # The index does not yet exist.
                    _create_index(name, expression)
                    continue

                if expression == db_indexes[name]:
                    # The index exists and is up to date.
                    continue
                # The index exists but the definition is not what expected, so
                # we delete it and add the proper index expression.
                d1 = store.delete_index(name)
                d1.addCallback(lambda _: _create_index(name, expression))

            all_created = defer.gatherResults(self._index_creation_deferreds)
            all_created.addCallback(_on_indexes_created)
            return all_created

        # Ask the database for currently existing indexes, and create them
        # if not found.
        d = store.list_indexes()
        d.addCallback(_create_indexes)
        return d


class SoledadMailAdaptor(SoledadIndexMixin):

    implements(IMailAdaptor)
    store = None

    indexes = indexes.MAIL_INDEXES
    mboxwrapper_klass = MailboxWrapper

    # Message handling

    def get_msg_from_string(self, MessageClass, raw_msg):
        """
        Get an instance of a MessageClass initialized with a MessageWrapper
        that contains all the parts obtained from parsing the raw string for
        the message.

        :param MessageClass: any Message class that can be initialized passing
                             an instance of an IMessageWrapper implementor.
        :type MessageClass: type
        :param raw_msg: a string containing the raw email message.
        :type raw_msg: str
        :rtype: MessageClass instance.
        """
        assert(MessageClass is not None)
        mdoc, fdoc, hdoc, cdocs = _split_into_parts(raw_msg)
        return self.get_msg_from_docs(
            MessageClass, mdoc, fdoc, hdoc, cdocs)

    def get_msg_from_docs(self, MessageClass, mdoc, fdoc, hdoc, cdocs=None):
        """
        Get an instance of a MessageClass initialized with a MessageWrapper
        that contains the passed part documents.

        This is not the recommended way of obtaining a message, unless you know
        how to take care of ensuring the internal consistency between the part
        documents, or unless you are glueing together the part documents that
        have been previously generated by `get_msg_from_string`.

        :param MessageClass: any Message class that can be initialized passing
                             an instance of an IMessageWrapper implementor.
        :type MessageClass: type
        :param fdoc: a dictionary containing values from which a
                     FlagsDocWrapper can be initialized
        :type fdoc: dict
        :param hdoc: a dictionary containing values from which a
                     HeaderDocWrapper can be initialized
        :type hdoc: dict
        :param cdocs: None, or a dictionary mapping integers (1-indexed) to
                      dicts from where a ContentDocWrapper can be initialized.
        :type cdocs: dict, or None

        :rtype: MessageClass instance.
        """
        assert(MessageClass is not None)
        return MessageClass(MessageWrapper(mdoc, fdoc, hdoc, cdocs))

    def _get_msg_from_variable_doc_list(self, doc_list, msg_class):
        if len(doc_list) == 2:
            fdoc, hdoc = doc_list
            cdocs = None
        elif len(doc_list) > 2:
            fdoc, hdoc = doc_list[:2]
            cdocs = dict(enumerate(doc_list[2:], 1))
        return self.get_msg_from_docs(msg_class, fdoc, hdoc, cdocs)

    def get_msg_from_mdoc_id(self, MessageClass, store, doc_id,
                             get_cdocs=False):
        metamsg_id = doc_id

        def wrap_meta_doc(doc):
            cls = MetaMsgDocWrapper
            return cls(doc_id=doc.doc_id, **doc.content)

        def get_part_docs_from_mdoc_wrapper(wrapper):
            d_docs = []
            d_docs.append(store.get_doc(wrapper.fdoc))
            d_docs.append(store.get_doc(wrapper.hdoc))
            for cdoc in wrapper.cdocs:
                d_docs.append(store.get_doc(cdoc))
            d = defer.gatherResults(d_docs)
            return d

        def get_parts_doc_from_mdoc_id():
            mbox = re.findall(constants.METAMSGID_MBOX_RE, doc_id)[0]
            chash = re.findall(constants.METAMSGID_CHASH_RE, doc_id)[0]

            def _get_fdoc_id_from_mdoc_id():
                return constants.FDOCID.format(mbox=mbox, chash=chash)

            def _get_hdoc_id_from_mdoc_id():
                return constants.FDOCID.format(mbox=mbox, chash=chash)

            d_docs = []
            fdoc_id = _get_fdoc_id_from_mdoc_id(doc_id)
            hdoc_id = _get_hdoc_id_from_mdoc_id(doc_id)
            d_docs.append(store.get_doc(fdoc_id))
            d_docs.append(store.get_doc(hdoc_id))
            d = defer.gatherResults(d_docs)
            return d

        if get_cdocs:
            d = store.get_doc(metamsg_id)
            d.addCallback(wrap_meta_doc)
            d.addCallback(get_part_docs_from_mdoc_wrapper)
        else:
            d = get_parts_doc_from_mdoc_id()

        d.addCallback(partial(self._get_msg_from_variable_doc_list,
                              msg_class=MessageClass))
        return d

    def create_msg(self, store, msg):
        """
        :param store: an instance of soledad, or anything that behaves alike
        :type store:
        :param msg: a Message object.

        :return: a Deferred that is fired when all the underlying documents
                 have been created.
        :rtype: defer.Deferred
        """
        wrapper = msg.get_wrapper()
        return wrapper.create(store)

    def update_msg(self, store, msg):
        """
        :param msg: a Message object.
        :param store: an instance of soledad, or anything that behaves alike
        :type store:
        :param msg: a Message object.
        :return: a Deferred that is fired when all the underlying documents
                 have been updated (actually, it's only the fdoc that's allowed
                 to update).
        :rtype: defer.Deferred
        """
        wrapper = msg.get_wrapper()
        return wrapper.update(store)

    # Mailbox handling

    def get_or_create_mbox(self, store, name):
        """
        Get the mailbox with the given name, or create one if it does not
        exist.

        :param name: the name of the mailbox
        :type name: str
        """
        index = indexes.TYPE_MBOX_IDX
        mbox = normalize_mailbox(name)
        return MailboxWrapper.get_or_create(store, index, mbox)

    def update_mbox(self, store, mbox_wrapper):
        """
        Update the documents for a given mailbox.
        :param mbox_wrapper: MailboxWrapper instance
        :type mbox_wrapper: MailboxWrapper
        :return: a Deferred that will be fired when the mailbox documents
                 have been updated.
        :rtype: defer.Deferred
        """
        return mbox_wrapper.update(store)

    def delete_mbox(self, store, mbox_wrapper):
        return mbox_wrapper.delete(store)

    def get_all_mboxes(self, store):
        """
        Retrieve a list with wrappers for all the mailboxes.

        :return: a deferred that will be fired with a list of all the
                 MailboxWrappers found.
        :rtype: defer.Deferred
        """
        return MailboxWrapper.get_all(store)


def _split_into_parts(raw):
    # TODO signal that we can delete the original message!-----
    # when all the processing is done.
    # TODO add the linked-from info !
    # TODO add reference to the original message?
    # TODO populate Default FLAGS/TAGS (unseen?)
    # TODO seed propely the content_docs with defaults??

    msg, parts, chash, size, multi = _parse_msg(raw)
    body_phash_fun = [walk.get_body_phash_simple,
                      walk.get_body_phash_multi][int(multi)]
    body_phash = body_phash_fun(walk.get_payloads(msg))
    parts_map = walk.walk_msg_tree(parts, body_phash=body_phash)
    cdocs_list = list(walk.get_raw_docs(msg, parts))
    cdocs_phashes = [c['phash'] for c in cdocs_list]

    mdoc = _build_meta_doc(chash, cdocs_phashes)
    fdoc = _build_flags_doc(chash, size, multi)
    hdoc = _build_headers_doc(msg, chash, parts_map)

    # The MessageWrapper expects a dict, one-indexed
    cdocs = dict(enumerate(cdocs_list, 1))

    return mdoc, fdoc, hdoc, cdocs


def _parse_msg(raw):
    msg = message_from_string(raw)
    parts = walk.get_parts(msg)
    size = len(raw)
    chash = sha256.SHA256(raw).hexdigest()
    multi = msg.is_multipart()
    return msg, parts, chash, size, multi


def _build_meta_doc(chash, cdocs_phashes):
    _mdoc = MetaMsgDocWrapper()
    _mdoc.fdoc = constants.FDOCID.format(mbox=INBOX_NAME, chash=chash)
    _mdoc.hdoc = constants.HDOCID.format(chash=chash)
    _mdoc.cdocs = [constants.CDOCID.format(phash=p) for p in cdocs_phashes]
    return _mdoc.serialize()


def _build_flags_doc(chash, size, multi):
    _fdoc = FlagsDocWrapper(chash=chash, size=size, multi=multi)
    return _fdoc.serialize()


def _build_headers_doc(msg, chash, parts_map):
    """
    Assemble a headers document from the original parsed message, the
    content-hash, and the parts map.

    It takes into account possibly repeated headers.
    """
    headers = defaultdict(list)
    for k, v in msg.items():
        headers[k].append(v)

    # "fix" for repeated headers.
    for k, v in headers.items():
        newline = "\n%s: " % (k,)
        headers[k] = newline.join(v)

    lower_headers = lowerdict(headers)
    msgid = first(_MSGID_RE.findall(
        lower_headers.get('message-id', '')))

    _hdoc = HeaderDocWrapper(
        chash=chash, headers=lower_headers, msgid=msgid)

    def copy_attr(headers, key, doc):
        if key in headers:
            setattr(doc, key, headers[key])

    copy_attr(lower_headers, "subject", _hdoc)
    copy_attr(lower_headers, "date", _hdoc)

    hdoc = _hdoc.serialize()
    # add parts map to header doc
    # (body, multi, part_map)
    for key in parts_map:
        hdoc[key] = parts_map[key]
    return stringify_parts_map(hdoc)
