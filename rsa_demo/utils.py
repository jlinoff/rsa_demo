'''
Local utilities.
'''
import argparse
import inspect
import sys


def err(msg: str, xcode: int=1):
    '''
    Output an error message and exit.
    '''
    lnum = inspect.stack()[1].lineno
    print(f'\033[31mERROR:{lnum}: {msg}\033[0m', file=sys.stderr)
    sys.exit(xcode)


def infov(opts: argparse.Namespace, msg: str):
    '''
    Output a verbose message.
    '''
    if opts.verbose > 0:
        lnum = inspect.stack()[1].lineno
        print(f'INFO:{lnum}: {msg}')


def infovv(opts: argparse.Namespace, msg: str):
    '''
    Output a very verbose message.
    '''
    if opts.verbose > 1:
        lnum = inspect.stack()[1].lineno
        print(f'INFO:{lnum}: {msg}')
