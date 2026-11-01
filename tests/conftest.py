from pathlib import Path
import gltest.direct.sdk_loader as sdk_loader

# Pin a release with a published universal archive; keep the cache in the workspace.
sdk_loader.CACHE_DIR = Path(__file__).resolve().parents[2] / 'genvm-cache'
sdk_loader.get_latest_version = lambda: 'v0.2.12'
