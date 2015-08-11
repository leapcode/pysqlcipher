# -*- coding: utf-8 -*-
# models.py
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
Generic Models to be used by the Document Adaptors.
"""
import copy


class SerializableModel(object):
    """
    A Generic document model, that can be serialized into a dictionary.

    Subclasses of this `SerializableModel` are meant to be added as class
    attributes of classes inheriting from DocumentWrapper.

    A subclass __meta__ of this SerializableModel might exist, and contain info
    relative to particularities of this model.

    For instance, the use of `__meta__.index` marks the existence of a primary
    index in the model, which will be used to do unique queries (in which case
    all the other indexed fields in the underlying document will be filled with
    the default info contained in the model definition).
    """

    @classmethod
    def serialize(klass):
        """
        Get a dictionary representation of the public attributes in the model
        class. To avoid collisions with builtin functions, any occurrence of an
        attribute ended in '_' (like 'type_') will be normalized by removing
        the trailing underscore.

        This classmethod is used from within the serialized method of a
        DocumentWrapper instance: it provides defaults for the
        empty document.
        """
        assert isinstance(klass, type)
        return _normalize_dict(klass.__dict__)


class DocumentWrapper(object):
    """
    A Wrapper object that can be manipulated, passed around, and serialized in
    a format that the store understands.
    It is related to a SerializableModel, which must be specified as the
    ``model`` class attribute.  The instance of this DocumentWrapper will not
    allow any other *public* attributes than those defined in the corresponding
    model.
    """
    # TODO we could do some very basic type checking here
    # TODO set a dirty flag (on __setattr__, whenever the value is != from
    # before)
    # TODO we could enforce the existence of a correct "model" attribute
    # in some other way (other than in the initializer)

    def __init__(self, **kwargs):
        if not getattr(self, 'model', None):
            raise RuntimeError(
                'DocumentWrapper class needs a model attribute')

        defaults = self.model.serialize()

        if kwargs:
            values = copy.deepcopy(defaults)
            values.update(_normalize_dict(kwargs))
        else:
            values = defaults

        for k, v in values.items():
            k = k.replace('-', '_')
            setattr(self, k, v)

    def __setattr__(self, attr, value):
        normalized = _normalize_dict(self.model.__dict__)
        if not attr.startswith('_') and attr not in normalized:
            raise RuntimeError(
                "Cannot set attribute because it's not defined "
                "in the model %s: %s" % (self.__class__, attr))
        object.__setattr__(self, attr, value)

    def serialize(self):
        return _normalize_dict(self.__dict__)

    def create(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    @classmethod
    def get_or_create(self):
        raise NotImplementedError()

    @classmethod
    def get_all(self):
        raise NotImplementedError()


def _normalize_dict(_dict):
    items = _dict.items()
    items = filter(lambda (k, v): not callable(v), items)
    items = filter(lambda (k, v): not k.startswith('_'), items)
    items = [(k, v) if not k.endswith('_') else (k[:-1], v)
             for (k, v) in items]
    items = [(k.replace('-', '_'), v) for (k, v) in items]
    return dict(items)
