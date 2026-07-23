#!/usr/bin/env python3
'''Logging / pretty-print helpers for the Diameter modules (mirrors GTP/5G).'''


def _emit(color, text, TAG=None, newLine=True):
    tag = ('[%s] ' % TAG) if TAG else ''
    msg = '\033[%sm%s%s\033[0m' % (color, tag, text)
    print(msg) if newLine else print(msg, end=' ')


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
