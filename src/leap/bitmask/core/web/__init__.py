try:
    import leap.bitmask_js
    assert leap.bitmask_js
    HAS_WEB_UI = True
except ImportError:
    HAS_WEB_UI = False

try:
    import txtorcon
    assert txtorcon
except Exception:
    pass
