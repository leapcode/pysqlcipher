:LastChangedDate: $LastChangedDate$
:LastChangedRevision: $LastChangedRevision$
:LastChangedBy: $LastChangedBy$

.. _cli:


Bitmask CLI
================================
``bitmaskctl`` is the command line interface.

It will try to launch the bitmask backend.

Creating an user
-----------------------------------

::

  bitmaskctl user create user@example.org

If the provider needs invite codes to register new users, you can pass one::
  
  bitmaskctl user create --invitecode xxxxxxx user@example.org


Authenticating 
-----------------------------------

To authenticate, start a session and start configured services::

  bitmaskctl user auth user@example.org


Uploading logs
---------------

(This needs ``pastebinit`` installed in your system) ::

  bitmaskctl logs send
