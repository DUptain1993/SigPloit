#!/usr/bin/env python3
'''
Shared, process-wide state for the 5G attack modules.
'''

# Records replies collected during a run, keyed by peer address. Each attack is
# free to populate this with whatever response detail it wants to report.
response_registry = {}


def reset_registry():
    response_registry.clear()
