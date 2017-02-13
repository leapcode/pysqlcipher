#!/usr/bin/env python
from pysqlcipher import dbapi2 as sqlite3


print 'module:', ".".join(map(str, sqlite3.version_info))
print 'sqlite:', ".".join(map(str, sqlite3.sqlite_version_info))

if True:
    # In-memory test

    SCHEMA = """
    create table folders
    (
        name        text not null,
        uidvalidity integer not null,

        primary key (name)
    );

    INSERT INTO "folders" VALUES('Archives',3314);
    INSERT INTO "folders" VALUES('Archives/2011',3315);
    """

    dbconn = sqlite3.connect(':memory:')
    dbconn.executescript(SCHEMA)

    folders = [
        'Archives',
        'Archives/2011',
        'Archives/2012'
    ]

else:
    # DB file
    dbconn = sqlite3.connect('bug.db')

    cur = dbconn.execute('select name from folders')
    folders = [row[0] for row in cur.fetchall()]


for folder in folders:

    dbconn.execute('begin')

    print folder
    cur = dbconn.execute('select uidvalidity from folders where name=?', (folder,))
    row = cur.fetchone()

    dbconn.commit()
