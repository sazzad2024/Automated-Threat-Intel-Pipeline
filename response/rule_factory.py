import datetime

def generate_yara(hash_list, threat_name):
    """
    Generates a valid YARA rule string using the hashes in the condition.
    """
    if not hash_list:
        return ""
    
    clean_name = threat_name.replace(" ", "_").replace(".", "_")
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    rule = f"""rule {clean_name}_HashItems {{
    meta:
        author = "ThreatMeta Platform"
        date = "{date_str}"
        adversary = "{threat_name}"
        description = "Auto-generated rule for {threat_name} hashes"
    
    strings:
"""
    
    for i, h in enumerate(hash_list):
        rule += f'        $s{i} = "{h}"\n'
        
    rule += """
    condition:
        any of them
}"""
    return rule

def generate_snort(ip_list, threat_name):
    """
    Returns a Snort rule that alerts on traffic from these IPs to $HOME_NET.
    """
    if not ip_list:
        return ""
        
    rules = []
    sid_start = 1000001 # Start SID for custom rules (example)
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    for i, ip in enumerate(ip_list):
        # alert ip <SRC> any -> $HOME_NET any (msg:"..."; sid:...;)
        sid = sid_start + i
        msg = f"Potential {threat_name} Activity Detected from {ip}"
        
        # Adding metadata as requested
        # Snort 2 style usually puts metadata in msg or class. Snort 3 has metadata keyword.
        # We will use standard Snort 2.x format but robust msg.
        rule = (f'alert ip {ip} any -> $HOME_NET any '
                f'(msg:"{msg}"; '
                f'metadata:author ThreatMeta, date {date_str}, adversary {threat_name}; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)')
        rules.append(rule)
        
    return "\n".join(rules)

def generate_suricata(ip_list, threat_name):
    """
    Returns a Suricata rule. Very similar to Snort but often supports more protocols/keywords.
    For this requirement, we'll ensure it uses Suricata specific flow keywords if applicable,
    or just standard compatible syntax.
    """
    if not ip_list:
        return ""
        
    rules = []
    sid_start = 2000001
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    for i, ip in enumerate(ip_list):
        sid = sid_start + i
        msg = f"ET CURRENT_EVENTS {threat_name} Inbound from {ip}"
        
        # Suricata supports 'flow' keyword which is good practice
        rule = (f'alert ip {ip} any -> $HOME_NET any '
                f'(msg:"{msg}"; flow:to_client,established; '
                f'reference:url,threat_meta_platform; '
                f'metadata:author ThreatMeta, date {date_str}, adversary {threat_name}; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)')
        rules.append(rule)
        
    return "\n".join(rules)
