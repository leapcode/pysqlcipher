:LastChangedDate: $LastChangedDate$
:LastChangedRevision: $LastChangedRevision$
:LastChangedBy: $LastChangedBy$

.. _bitmask_core:

============
Bitmask Core
============

The bitmask core daemon can be launched like this::

  bitmaskd

The command-line program, ``bitmaskctl``, and the GUI, will launch the
daemon when needed.

Starting the API server
=======================

If configured to do so, the bitmask core will expose all of the commands
throught a REST API. In bitmaskd.cfg::

  [services]
  web = True


Resources
========= 

Following is a list of currently available resources and a brief description of
each one. For details click on the resource name.

+-----------------------------------+---------------------------------+
| Resource                          | Description                     |
+===================================+=================================+
| ``POST`` :ref:`cmd_core_version`  | Get Bitmask Core Version Info   |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_core_stats`    | Get Stats about Bitmask Usage   |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_core_status`   | Get Bitmask Status              |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_core_stop`     | Stop Bitmask Core               |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_prov_list`     | List all providers              |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_prov_create`   | Create a new provider           |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_prov_read`     | Get info about a provider       |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_prov_del`      | Delete a given provider         |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_list`     | List all users                  |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_active`   | Get active user                 |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_create`   | Create a new user               |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_update`   | Update an user                  |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_auth`     | Authenticate an user            |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_user_logout`   | End session for an user         |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_keys_list`     | Get all known keys for an user  |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_keys_insert`   | Insert a new key                |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_keys_del`      | Delete a given key              |
+-----------------------------------+---------------------------------+
| ``POST`` :ref:`cmd_keys_export`   | Export keys                     |
+-----------------------------------+---------------------------------+

.. _cmd_core_version:

/core/version
-------------
**POST /core/version**

  Get Bitmask Core Version Info

.. _cmd_core_stats:

/core/stats
-----------
**POST /core/stats**

  Get Stats about Bitmask Usage

.. _cmd_core_status:

/core/status
------------
**POST /core/status**

  Get Bitmask status

.. _cmd_core_stop:

/core/stop
----------
**POST /core/stop**

  Stop Bitmask core (daemon shutdown).

.. _cmd_prov_list:

/bonafide/provider/list
-----------------------
**POST /bonafide/provider/list**

  List all known providers.

.. _cmd_prov_create:

/bonafide/provider/create
--------------------------
**POST /bonafide/provider**

  Create a new provider.

.. _cmd_prov_read:

/bonafide/provider/read
-----------------------
**POST /bonafide/provider/read**

  Get info bout a given provider.

.. _cmd_prov_del:

/bonafide/provider/delete
-------------------------
**POST /bonafide/provider/delete**

  Delete a given provider.


.. _cmd_user_list:

/bonafide/user/list
-------------------
**POST /bonafide/user/list**

  List all the users known to the local backend. 

  **Form parameters**:
        * ``foo`` *(required)* - foo bar.
        * ``bar`` *(optional)* - foo bar.

  **Status codes**:
        * ``200`` - no error

.. _cmd_user_active:

/bonafide/user/active
---------------------
**POST /bonafide/user/active**

  Get the active user.

.. _cmd_user_create:

/bonafide/user/create
---------------------
**POST /bonafide/user/create**

  Create a new user.

  **Form parameters**:
        * ``foo`` *(required)* - foo bar.

.. _cmd_user_update:

/bonafide/user/update
---------------------
**POST /bonafide/user/update**

  Update a given user.

.. _cmd_user_auth:

/bonafide/user/authenticate
---------------------------
**POST /bonafide/user/authenticate**

  Authenticate an user.

.. _cmd_user_logout:

/bonafide/user/logout
---------------------
**POST /bonafide/user/logout**

  Logs out an user, and destroys its local session.

.. _cmd_keys_list:

/keys/list
-------------------
**POST /keys/list**

  Get all keys for an user.

.. _cmd_keys_insert:

/keys/insert/
-------------------
**POST /keys/insert**

  Insert a new key for an user.

.. _cmd_keys_del:

/keys/delete/
-------------------
**POST /keys/delete**

  Delete a key for an user.

.. _cmd_keys_export:

/keys/export/
-------------------
**POST /keys/export**

  Export keys for an user.


API Authentication
==================

(TBD) Most of the resources in the API are protected by an authentication token.
