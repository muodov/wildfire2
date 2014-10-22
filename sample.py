import random
import sys
someconst = 3

def inc(x):
    return x + 1

def very_understandable_function(x=5):
    def get_eleet():
        return x

    import platform
    print 'Hello, %s (%s)' % (platform.platform(), platform.architecture()[0])
    r = 10
    print 'I like doing stuff with number: %r' % (r % 42)

    for i in range(r):
        print i + get_eleet(), get_eleet()

    if (r % 10):
        print 'wUuUUt'
    else:
        print 'dont care!'

    with open('success', 'w') as f:
        f.write('yoooo seems to work bra!')

    return 0xdeadbeef
#print 'aaa'
class NewStyleClass(object):
    #print 'newstyle'
    def __init__(self):
        super(NewStyleClass, self).__init__()
    def doit(self):
        print 'i am new'

class NewStyleClassCustomInit(object):
    #print 'newstyle'
    def __init__(self):
        pass
    def doit(self):
        print 'i am new'
#print 'between'
class OldStyleClass:
    #print 'oldstyle'
    def doit(self):
        print 'i am old'


#print 'bbb'
def generate_random_strings():
    """Generate a random string"""
    print 'ucucuga'
    charset = map(chr, range(0, 0x100))
    print 'ucucuga1'
    return ''.join(random.choice(charset) for i in range(random.randint(10, 100)))

if __name__ == '__main__':
    very_understandable_function(293)
    NewStyleClass().doit()
    OldStyleClass().doit()
    for i in xrange(10):
        print inc(i)
    generate_random_strings()
    print someconst
