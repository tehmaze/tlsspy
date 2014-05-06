from collections import OrderedDict, MutableSet
import datetime
import os
import Queue
import threading

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import char, univ

from tlsspy.asn1_models import x509
from tlsspy.log import log
from tlsspy.oids import friendly_oid

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
    b = bytearray(os.urandom(size))
    assert len(b) == size
    return b


class OrderedSet(MutableSet):
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
    pass


class ThreadPool(object):
    Done = ThreadPoolDone

    def __init__(self):
        self._active_threads = 0
        self._jobs           = Queue.Queue()
        self._results        = Queue.Queue()
        self._threads        = []

    def add_job(self, func, args):
        self._jobs.put((func, args))

    def get_results(self):
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
        self._jobs.join()
        self._active_threads = 0
        self._results.join()

    def start(self, workers):
        log.info('Starting {} thread pool workers'.format(workers))
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
                log.debug('[{}] done'.format(
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
                log.error('Uncaught exception in thread worker: {}'.format(
                    error,
                ))
            else:
                results.put(result)
            finally:
                jobs.task_done()
