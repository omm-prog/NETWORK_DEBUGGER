def safe_getattr(obj, name, default=None):
    try:
        return getattr(obj, name)
    except Exception:
        return default
