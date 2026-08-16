import hashlib

def generate_finding_fingerprint(project_id, asset_id, testing_module_key, category, title, location):
    """
    Generates a deterministic SHA256 hash identifying the same vulnerability across multiple scans.
    """
    p_str = str(project_id or '').strip()
    a_str = str(asset_id or '').strip()
    m_str = str(testing_module_key or '').strip()
    c_str = str(category or '').strip().upper()
    t_str = str(title or '').strip().lower()
    l_str = str(location or '').strip().lower()
    
    raw = f"{p_str}:{a_str}:{m_str}:{c_str}:{t_str}:{l_str}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()
