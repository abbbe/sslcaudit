# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, time
from threading import Thread

class Hammer(Thread):
    '''
    This is an abstract class for hammering, normally used for unit tests only.
    '''
    logger = logging.getLogger('Hammer')

    HAMMERING_DELAY = 0.5

    def __init__(self, nattempts):
        Thread.__init__(self, target=self.run)
        self.nattempts = nattempts

        self.daemon = True
        self.should_stop = False

    def run(self):
        self.logger.debug("running %s", self)

        i = 0
        while (self.nattempts == -1 or i < self.nattempts) and not self.should_stop:
            # connect to the peer, do something, disconnect
            try:
                self.logger.debug("start hammering round %d to target %s", i, self.peer)
                self.hammer(i)
                self.logger.debug("stopped hammering round %d to target %s", i, self.peer)
            except Exception as ex:
                self.logger.error('error hammering round %d target %s: %s', i, self.peer, ex)

            # wait a little while before repeating
            time.sleep(self.HAMMERING_DELAY)

            i += 1
        self.logger.debug("exiting %s", self)

    def hammer(self, round):
        '''
        This method can be overridden by subclasses to do something useful. Round parameter contains a sequence
        number of the invocation of this method.
        '''
        raise NotImplemented('subclasses must override this method')

    def stop(self):
        self.logger.debug("stopping %s", self)
        self.should_stop = True
