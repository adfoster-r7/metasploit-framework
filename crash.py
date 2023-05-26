# import atexit
# import sys
#
# def on_exit():
#     print('ended')
#     print(sys.exc_info())
#
# atexit.register(on_exit)
#
# raise Exception('oh no')

import sys
import traceback

def debug_print(msg):
    print(msg)

def handle_exception(exc_type, exc_value, exc_traceback):
  debug_print('unhandled exception caught:')
  debug_print(''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
  sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = handle_exception

def foo():
    debug_print(__name__)
    raise 'testing'

foo()
