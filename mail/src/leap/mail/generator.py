from email.generator import Generator as EmailGenerator


class Generator(EmailGenerator):
    """
    Generates output from a Message object tree, keeping signatures.

    This code was extracted from Mailman.Generator.Generator, version 2.1.4:

    Most other Generator will be created not setting the foldheader flag,
    as we do not overwrite clone(). The original clone() does not
    set foldheaders.

    So you need to set foldheaders if you want the toplevel to fold headers

    TODO: Python 3.3 is patched against this problems. See issue 1590744 on
          python bug tracker.
    """
    def _write_headers(self, msg):
        for h, v in msg.items():
            print >> self._fp, '%s:' % h,
            print >> self._fp, v
        print >> self._fp
