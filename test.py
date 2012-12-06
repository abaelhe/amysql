import amysql
c=amysql.Con()
c.connect('localhost',3306, 'xweb', 'xweb123', 'xweb')
from time import time
def pf(func, n):
    t=time()
    for i in xrange(n):
        func()
    d=time()
    return n/(d-t)

print pf(lambda:c.query("select * from sys_usr"), 10000)
