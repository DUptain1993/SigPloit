#!/usr/bin/env python3
'''
Logging / pretty-print helpers for the 5G modules.

These mirror the helper signatures used by the GTP package
(gtp/gtp_v2_core/utilities/utilities.py) so the 5G attack code reads the same
way as the rest of SigPloit.
'''
import datetime
import time


def _timestamp():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')


def _emit(color, text, TAG=None, newLine=True):
    tag = ('[%s] ' % TAG) if TAG else ''
    msg = '\033[%sm%s%s\033[0m' % (color, tag, text)
    if newLine:
        print(msg)
    else:
        print(msg, end=' ')


def logNormal(text, verbose=False, TAG=None, newLine=True):
    if verbose:
        _emit('0', text, TAG, newLine)


def logOk(text, verbose=True, TAG=None, newLine=True):
    _emit('0;32', text, TAG, newLine)


def logWarn(text, verbose=True, TAG=None, newLine=True):
    _emit('1;33', text, TAG, newLine)


def logErr(text, TAG=None, newLine=True):
    _emit('0;31', text, TAG, newLine)


def logInfo(text, TAG=None, newLine=True):
    _emit('0;34', text, TAG, newLine)
