import atexit
import inspect
import os
from pathlib import Path
import gltest.direct.sdk_loader as sdk_loader

# Official SDK release with a published universal archive.
sdk_loader.CACHE_DIR = Path(os.environ.get('GENLAYER_TEST_CACHE', Path.home() / '.cache' / 'genlayer-v2-tests'))
sdk_loader.get_latest_version = lambda: 'v0.2.12'

# genlayer-test 0.29.2 unlinks an open stdin file: legal on Linux, WinError32
# on Windows. Patch only that cleanup instruction in memory, never package files.
if os.name == 'nt':
    import gltest.direct.loader as loader
    pending = []

    def deferred_unlink(path):
        try:
            os.unlink(path)
        except PermissionError:
            pending.append(path)

    def cleanup():
        for path in pending:
            try:
                os.unlink(path)
            except (FileNotFoundError, PermissionError):
                pass

    source = inspect.getsource(loader._inject_message_to_fd0)
    if source.count('os.unlink(path)') != 1:
        raise RuntimeError('Unexpected test framework version: review Windows shim')
    loader._deferred_unlink = deferred_unlink
    exec(source.replace('os.unlink(path)', '_deferred_unlink(path)'), loader.__dict__)
    atexit.register(cleanup)
