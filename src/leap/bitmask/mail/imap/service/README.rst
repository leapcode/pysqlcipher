testing the service
===================

Run the twisted service::

        twistd -n -y imap-server.tac

And use offlineimap for tests::

        offlineimap -c LEAPofflineimapRC-tests

minimal offlineimap configuration
---------------------------------

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
remoteport = 9930
remoteuser = user
remotepass = pass

debugging
---------

Use ngrep to obtain logs of the sequences::

        sudo ngrep -d lo -W byline port 9930
