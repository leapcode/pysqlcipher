.. _mail_journey:

The life cycle of a LEAP Email
==============================
The following are just some notes to facilitate the understanding of the
leap.mail internals to developers and collaborators.

Server-side: receiving mail from the outside world
--------------------------------------------------

1. the mx server receives an email, it gets through all the postfix validation and it's written into disk
2. ``leap_mx`` gets that write in disk notification and encrypts the incoming mail to its intended recipient's pubkey
3. that encrypted blob gets written into couchdb in a way soledad will catch it in the next sync


Client-side: fetching and processing incoming email
---------------------------------------------------
you have an imap and an smtp local server. For IMAP:

1. soledad syncs
2. **fetch** module sees if there's new encrypted mail for the current user from leap_mx
3. if there is, the mail is decrypted using the user private key, and splitted
   into several parts according to the internal mail data model (separating
   mutable and inmutable email parts). Those documents it encrypts it properly
   like other soledad documents and deletes the pubkey encrypted doc
4. desktop client is notified that there are N new mails 
5. when a MUA connects to the **imap** local server, the different documents are glued
   together and presented as response to the different imap commands.


Client side: sending email
--------------------------

1. you write an email to a recipient and hit send
2. the **smtp** local server gets that mail, it checks from whom it is and to whom it is for
3. it signs the mail with the ``From:``'s privkey
4. it retrieves ``To:``'s pubkey with the keymanager and if it finds it encrypts the mail to him/her
5. if it didn't find it and you don't have your client configured to "always encrypt", it goes out with just the signature
6. else, it fails out complaining about this conflict
7. that mail gets relayed to the provider's **smtp** server
