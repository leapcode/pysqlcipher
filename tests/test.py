from pysqlcipher import dbapi2 as sqlite
conn = sqlite.connect('test.db')
c = conn.cursor()
c.execute("PRAGMA key='testaverylongpasswordisthisokey'")
c.execute("create table stocks (date text, trans text, symbol text, qty real, price real)")
c.execute("""insert into stocks values ('2006-01-05','BUY','RHAT',100,35.14)""")
conn.commit()
c.close()
