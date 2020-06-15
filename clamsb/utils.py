# Copyright (C) 2019-2020  Cisco Systems, Inc. and/or its affiliates. All rights reserved.
import inspect
import os.path
import logging
import resource
import time

def setup_logging(debug=False, verbose=False, logfile=None):
    """set up logging environment
    """
    root_log = logging.getLogger()          # grab the root logger
    if debug:
        root_log.setLevel(logging.DEBUG)
    elif verbose:
        root_log.setLevel(logging.INFO)
    else:
        root_log.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    logformat = "%(name)s: %(levelname)s: %(message)s"
    if logfile:
        handler = logging.FileHandler(logfile)
        logformat = "%(asctime)s %(levelname)s:%(name)s:%(message)s"
    handler.setFormatter(logging.Formatter(logformat))
    root_log.addHandler(handler)
    return root_log


class Timer(object):
    def __init__(self, desc):
        self.desc = desc
        self.reset()

    def start(self):
        self._start = time.time()

    def split(self):
        if self._end < self._start:
            return time.time() - self._start
        return self._end - self._start

    def time(self):
        if self._end < self._start:
            return time.time() - self._start
        return self._end - self._start

    def stop(self):
        self._end = time.time()
        return self._end - self._start

    def reset(self):
        self._start = 0.0
        self._end = 0.0

    def __repr__(self):
        return str(self.split())

    @property
    def human_readable(self):
        remain = self.split()
        hours = int(remain / 3600.0)
        remain %= 3600
        minutes = int(remain // 60.0)
        seconds = remain % 60.0
        secstr = "{0:.3f}".format(seconds)
        return "{} {}:{}:{}".format(self.desc, hours, minutes, secstr)
