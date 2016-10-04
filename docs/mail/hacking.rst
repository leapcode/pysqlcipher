.. _hacking:

Hacking  on Bitmask Mail
========================

Some hints oriented to `leap.mail` hackers. These notes are mostly related to
the imap server, although they probably will be useful for other pieces too.

Don't panic! Just manhole into it
---------------------------------


If you want to inspect the objects living in your application memory, in
realtime, you can manhole into it.

First of all, check that the modules ``PyCrypto`` and ``pyasn1`` are installed
into your system, they are needed for it to work.

You just have to pass the ``LEAP_MAIL_MANHOLE=1`` enviroment variable while
launching the client::

  LEAP_MAIL_MANHOLE=1 bitmask --debug

And then you can ssh into your application! (password is "leap")::

  ssh boss@localhost -p 2222

Did I mention how *awesome* twisted is?? ``:)``


Profiling
----------

If using ``twistd`` to launch the server, you can use twisted profiling
capabities::

  LEAP_MAIL_CONFIG=~/.leapmailrc twistd --profile=/tmp/mail-profiling -n -y imap-server.tac

``--profiler`` option allows you to select different profilers (default is
"hotshot").

You can also do profiling when using the ``bitmask`` client. Enable the
``LEAP_PROFILE_IMAPCMD`` environment flag to get profiling of certain IMAP
commands::

 LEAP_PROFILE_IMAPCMD=1 bitmask --debug


Mutt config
------------

You cannot live without mutt? You're lucky! Use the following minimal config
with the imap service::

 set folder="imap://user@provider@localhost:1984"
 set spoolfile="imap://user@provider@localhost:1984/INBOX"
 set ssl_starttls = no
 set ssl_force_tls = no
 set imap_pass=MAHSIKRET



Debugging IMAP
------------------------------
After IMAP service is running, you can telnet into your local IMAP server and read your mail like a real programmer™::

  % telnet localhost 1984
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  * OK [CAPABILITY IMAP4rev1 LITERAL+ IDLE NAMESPACE] Twisted IMAP4rev1 Ready
  tag LOGIN me@myprovider.net mahsikret
  tag OK LOGIN succeeded
  tag SELECT Inbox
  * 2 EXISTS
  * 1 RECENT
  * FLAGS (\Seen \Answered \Flagged \Deleted \Draft \Recent List)
  * OK [UIDVALIDITY 1410453885932] UIDs valid
  tag OK [READ-WRITE] SELECT successful
  ^]
  telnet> Connection closed.


Although you probably prefer to use ``offlineimap`` for tests:: 

  offlineimap -c LEAPofflineimapRC-tests


Use ``ngrep`` to obtain live logs of the commands and responses::

  sudo ngrep -d lo -W byline port 1984


Thunderbird
---------------------------

To get verbose output from thunderbird/icedove, set the following environment
variable::

  NSPR_LOG_MODULES="imap:5" icedove


Minimal offlineimap configuration
---------------------------------

You can use this as a sample offlineimap config file::

  [general]
  accounts = leap-local

  [Account leap-local]
  localrepository = LocalLeap
  remoterepository = RemoteLeap

  [Repository LocalLeap]
  type = Maildir
  localfolders = ~/LEAPMail/Mail

  [Repository RemoteLeap]
  type = IMAP
  ssl = no
  remotehost = localhost
  remoteport = 1984
  remoteuser = user
  remotepass = pass

Testing utilities
-----------------
There are a bunch of utilities to test IMAP delivery in ``imap/tests`` folder.
If looking for a quick way of inspecting mailboxes, have a look at ``getmail``::

 ./getmail me@testprovider.net mahsikret
 1. Drafts
 2. INBOX
 3. Trash
 Which mailbox? [1] 2
 1 Subject: this is the time of the revolution
 2 Subject: ignore me

 Which message? [1] (Q quits) 1
 1 X-Leap-Provenance: Thu, 11 Sep 2014 16:52:11 -0000; pubkey="C1F8DE10BD151F99"
 Received: from mx1.testprovider.net(mx1.testprovider.net [198.197.196.195])
 (using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
 (Client CN "*.foobar.net", Issuer "Gandi Standard SSL CA" (not verified))
 by blackhole (Postfix) with ESMTPS id DEADBEEF
 for <me@testprovider.net>; Thu, 11 Sep 2014 16:52:10 +0000 (UTC)
 Delivered-To: 926d4915cfd42b6d96d38660c04613af@testprovider.net
 Message-Id: <20140911165205.GB8054@samsara>
 From: Kali <kali@leap.se>
 
 (snip)

IMAP Message Rendering Regressions
----------------------------------

For testing the IMAP server implementation, there is a litte regressions script
that needs some manual work from your side.

First of all, you need an already initialized account. Which for now basically
means you have created a new account with a provider that offers the Encrypted
Mail Service, using the Bitmask Client wizard. Then you need to log in with that
account, and let it generate the secrets and sync with the remote for a first
time. After this you can run the twistd server locally and offline.

From the ``leap.mail.imap.tests`` folder, and with an already initialized server
running::

  ./regressions_mime_struct user@provider pass path_to_samples/

You can find several message samples in the ``leap/mail/tests`` folder.
 


