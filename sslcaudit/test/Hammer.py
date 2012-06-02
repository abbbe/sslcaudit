# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, time
from threading import Thread
import threading

class Hammer(object):
    '''
    This is an abstract class for hammering, normally used for unit tests only.
    '''
    logger = logging.getLogger('Hammer')

    HAMMERING_DELAY = 0.1

    def __init__(self, nattempts, nparallel=10):
        self.nattempts = nattempts
        self.nparallel = nparallel
        self.next_round = 0
        self.lock = threading.Lock()  # this lock has to be acquired before use of 'next_round' attribute

        self.daemon = True
        self.should_stop = False

        self.hammer_threads = []
        nthreads = self.nparallel if (nattempts < 0) or (self.nparallel < nattempts) else nattempts
        for _ in range(nthreads):
            self.hammer_threads.append(Thread(target=self.run))

    def start(self):
        for thread in self.hammer_threads:
            thread.start()
            self.logger.debug("spawned thread %s", thread)

    def run(self):
        '''
        This method is a target of multiple threads running in parallel.
        '''
        self.logger.debug("running, thread %s", threading.currentThread())

        while True:
            # get ourselves a round id
            with self.lock:
                if self.should_stop:
                    # quitting this thread because we were requested to
                    self.logger.debug("exiting (should_stop is True), thread %s", threading.currentThread())
                    return
                elif (self.nattempts > 0) and (self.next_round >= self.nattempts):
                    # quitting this thread because too many rounds are made already
                    self.logger.debug("exiting (next_round  %d > nattempts %d), thread %s",
                        self.next_round, self.nattempts,
                        threading.currentThread())
                    return
                else:
                    this_nround = self.next_round
                    self.next_round += 1

            self.logger.debug("invoking hammer(), thread %s", threading.currentThread())
            self.hammer(this_nround)

            # wait a little while before repeating
            time.sleep(self.HAMMERING_DELAY)

    def hammer(self, round):
        '''
        This method can be overridden by subclasses to do something useful. Round parameter contains a sequence
        number of the invocation of this method.
        '''
        raise NotImplemented('subclasses must override this method')

    def stop(self):
        self.logger.debug("stopping %s", self)
        self.should_stop = True

    def spawn_hammer_thread(self, nround):
        # connect to the peer, do something, disconnect
        try:
            self.logger.debug("start hammering %s (round %i)", self.peer, nround)
            self.hammer(nround)
            self.logger.debug("stopped hammering %s (round %d)", self.peer, nround)
        except Exception as ex:
            self.logger.error('error hammering %s (round %d): %s', self.peer, nround, ex)
