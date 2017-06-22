from pysqlcipher import dbapi2

c = dbapi2.connect(":memory:")
cur = c.execute("pragma compile_options")

lines = cur.fetchall()
flags = [l[0] for l in lines]
for flag in flags:
    print flag
assert "HAVE_USLEEP" in flags
assert "ENABLE_LOAD_EXTENSION" in flags

