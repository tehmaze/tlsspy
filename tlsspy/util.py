from collections import OrderedDict, MutableSet
import datetime
import math
import os
import Queue
import threading

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import char, univ

from tlsspy.asn1_models import x509
from tlsspy.log import log
from tlsspy.oids import friendly_oid

try:
    if 'SKIP_GMPY' in os.environ:
        raise ImportError()
    import gmpy
    has_gmpy = True
except ImportError:
    log.warning('Could not load gmpy, calculations may be slow(er)')
    has_gmpy = False


ASN1_GENERALIZEDTIME = (
    r'%Y%m%d%H%M%SZ',
    r'%Y%m%d%H%M%S%z',
)


def merge(a, b):
    '''Recursively merge two dictionaries.'''
    for key in set(a.keys()).union(b.keys()):
        if key in a and key in b:
            yield (key, dict(merge(a[key], b[key])))
        elif key in a:
            yield (key, a[key])
        else:
            yield (key, b[key])


def get_random_bytes(size):
    '''
    Get ``size`` of random bytes.
    '''
    b = bytearray(os.urandom(size))
    assert len(b) == size
    return b


class OrderedSet(MutableSet):
    '''
    Set that remembers the original insertion order.
    '''

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]  # sentinel
        self.map = {}

        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, key):
        if key not in self.map:
            end = self.end
            cur = end[1]
            cur[2] = end[1] = self.map[key] = [key, cur, end]

    def discard(self, key):
        if key in self.map:
            key, prv, nxt = self.map.pop(key)
            prv[2] = nxt
            nxt[1] = prv

    def __iter__(self):
        end = self.end
        cur = end[2]
        while cur is not end:
            yield cur[0]
            cur = cur[2]

    def __reversed__(self):
        end = self.end
        cur = end[1]
        while cur is not end:
            yield cur[0]
            cur = cur[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('Empty set')

        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        else:
            return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        else:
            return set(self) == set(other)


class ThreadPoolDone(object):
    '''
    Sentinel object for the :class:`ThreadPool` workers to notify they are
    done processing.
    '''
    pass


class ThreadPool(object):
    '''
    Pool of threaded workers.
    '''

    Done = ThreadPoolDone

    def __init__(self):
        self._active_threads = 0
        self._jobs           = Queue.Queue()
        self._results        = Queue.Queue()
        self._threads        = []

    def add_job(self, func, args):
        '''
        Queue a new function for processing by a worker.

        :arg func: callable function
        :arg args: tuple of arguments
        '''
        self._jobs.put((func, args))

    def get_results(self):
        '''
        Generator function returning all the results from the workers until
        they are done processing.
        '''
        active_threads = self._active_threads
        while active_threads or not self._results.empty():
            result = self._results.get()
            if isinstance(result, ThreadPool.Done):
                active_threads -= 1
                self._results.task_done()
                continue

            else:
                self._results.task_done()
                yield result

    def join(self):
        '''
        Wait for all the workers to finish.
        '''
        self._jobs.join()
        self._active_threads = 0
        self._results.join()

    def start(self, workers):
        '''
        Start workers in the thread pool.

        :arg workers: number of workers
        '''
        log.info('Starting {0} thread pool workers'.format(workers))
        if self._active_threads:
            raise SyntaxError('Already started')

        for x in xrange(workers):
            worker = threading.Thread(
                target=self._work,
                args=(self._jobs, self._results),
                name='worker_{:03d}'.format(x),
            )
            worker.start()
            self._threads.append(worker)
            self._active_threads += 1

        for worker in self._threads:
            self._jobs.put(ThreadPool.Done())

        log.info('Done starting workers')

    def _work(self, jobs, results):
        while True:
            job = jobs.get()

            if isinstance(job, ThreadPool.Done):
                log.debug('[{0}] done'.format(
                    threading.currentThread().name,
                ))
                # Bye!
                results.put(ThreadPool.Done())
                jobs.task_done()
                break

            func = job[0]
            args = job[1]
            try:
                result = func(*args)
            except Exception as error:
                log.error('Uncaught exception in thread worker: {0}'.format(
                    error,
                ))
            else:
                results.put(result)
            finally:
                jobs.task_done()


def bytes_to_long(b):
    '''
    Convert a byte sequence to its long value.

    >>> bytes_to_long('\x42\x2a')
    16938L
    '''
    total = 0L
    multi = 1L
    for count in range(len(b) - 1, -1, -1):
        value = b[count]
        total += multi * value
        multi <<= 8
    return total


def long_to_bytes(n, limit=None):
    '''
    Convert a long value to a byte sequence in big endian.

    >>> long_to_bytes(16938)
    bytearray('B*')
    >>> long_to_bytes(16938, 1)
    bytearray('*')
    '''
    if limit == None:
        limit = num_bytes(n)

    b = bytearray(limit)
    for count in range(limit - 1, -1, -1):
        b[count] = int(n % 256)
        n >>= 8
    return b


def num_bits(n):
    r'''
    Returns the number of bits used to generated number ``n``. Calculates:

    .. math::
        \log(n, 2) - 1
    '''
    if n == 0:
        return 0
    else:
        s = '{0:x}'.format(n)
        return ((len(s) - 1) * 4) + {
            '0': 0, '1': 1, '2': 2, '3': 2,
            '4': 3, '5': 3, '6': 3, '7': 3,
        }.get(s[0], 4)


def num_bytes(n):
    r'''
    Returns the number of bytes used to generate number ``n``. Calculates:

    .. math::
        \providecommand{\ceil}[1]{\left \lceil #1 \right \rceil }
        \ceil{(log(n, 2) - 1)/8}
    '''
    if n == 0:
        return 0
    else:
        bits = num_bits(n)
        return int(math.ceil(bits / 8.0))


def inv_mod(a, b):
    '''
    Inverse of :math:`a \mod b` using the Extended Euclidean Algorithm:

    .. math::
        ax + by = \gcd(a, b)
    '''
    c, d = a, b
    uc, ud = 1, 0

    while c != 0:
        q = d // c
        c, d = d - (q * c), c
        uc, ud = ud - (q * uc), uc

    if d == 1:
        return ud % b
    else:
        return 0


def pow_mod(b, p, m):
    '''
    Power with modulus.

    :arg b: base
    :arg p: power
    :arg m: modulus

    For :math:`p < 0`:

    .. math::
        (b^p \mod m) \pmod m

    For :math:`p >= 0`:

    .. math::
        b^p \mod m
    '''
    if has_gmpy:
        b = gmpy.mpz(b)
        p = gmpy.mpz(p)
        m = gmpy.mpz(m)
        return long(pow(b, p, m))

    elif p < 0:
        return inv_mod(pow(b, p, m), m)

    else:
        return pow(b, p, m)
