import dns.resolver
import base64
import struct

def check_spf(domain):
    print("\n[*] Checking SPF Record against Bitsight Criteria...")
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for record in txt_records:
            record_text = record.to_text().strip('"')
            if record_text.startswith("v=spf1"):
                spf_record = record_text
                break
        
        if not spf_record:
            print("    \033[91m[✗] SPF Record: NOT FOUND\033[0m")
            print("        -> Bitsight Grade Impact: BAD / RISK (High exposure to email spoofing).")
            return

        print(f"    \033[92m[✓] SPF Record Found:\033[0m {spf_record}")
        
        if "+all" in spf_record:
            print("    \033[91m[✗] Bitsight Rule Violation: Record ends with '+all' (Allows broad spoofing).\033[0m")
        elif "?all" in spf_record:
            print("    \033[93m[!] Bitsight Warning: Record ends with '?all' (Neutral / Incomplete enforcement).\033[0m")
        elif "-all" in spf_record or "~all" in spf_record:
            print("    \033[92m[✓] BitSight Rule Pass: Secure qualifier configured (-all / ~all).\033[0m")
        else:
            print("    \033[91m[✗] BitSight Rule Violation: Missing explicit fall-through mechanism (all).\033[0m")
            
        lookup_mechanisms = ["include:", "a:", "mx:", "exists:", "redirect="]
        lookup_count = sum(spf_record.count(mech) for mech in lookup_mechanisms)
        
        if lookup_count > 10:
            print(f"    \033[91m[✗] Bitsight Rule Violation: Too many DNS lookups ({lookup_count}/10 limit exceeded). Causes PermError.\033[0m")
        else:
            print(f"    \033[92m[✓] Bitsight Rule Pass: DNS lookup count is compliant ({lookup_count}/10).")
            
        if "ptr" in spf_record.lower():
            print("    \033[91m[✗] Bitsight Rule Violation: Contains 'ptr' mechanism (Deprecated, slow, and insecure).\033[0m")

    except Exception as e:
        print(f"    \033[91m[✗] Error fetching SPF record: {e}\033[0m")


def check_dmarc(domain):
    print("\n[*] Checking DMARC Record against Bitsight Criteria...")
    dmarc_domain = f"_dmarc.{domain}"
    try:
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = None
        for record in txt_records:
            record_text = record.to_text().strip('"')
            if record_text.startswith("v=DMARC1"):
                dmarc_record = record_text
                break
                
        if not dmarc_record:
            print("    \033[91m[✗] DMARC Record: NOT FOUND\033[0m")
            print("        -> Bitsight Grade Impact: BAD / RISK (No domain spoofing protection protocol).")
            return

        print(f"    \033[92m[✓] DMARC Record Found:\033[0m {dmarc_record}")
    
        tags = {}
        for part in dmarc_record.split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                tags[k.strip().lower()] = v.strip()
        
        p_policy = tags.get('p')
        if p_policy == "reject":
            print("    \033[92m[✓] Bitsight Rule Pass: Policy set to REJECT (Maximum protection score).\033[0m")
        elif p_policy == "quarantine":
            pct = tags.get('pct', '100')
            if pct != '100':
                print(f"    \033[93m[!] Bitsight Warning: Policy is QUARANTINE but pct={pct} reduces enforcement strength.\033[0m")
            else:
                print("    \033[92m[✓] Bitsight Rule Pass: Policy set to QUARANTINE (100% enforcement).\033[0m")
        elif p_policy == "none":
            print("    \033[93m[!] Bitsight Warning: Policy set to NONE (Monitoring mode only - Zero defensive enforcement score).\033[0m")
        else:
            print("    \033[91m[✗] Bitsight Rule Violation: Missing or invalid policy 'p=' tag.\033[0m")
            
        if 'rua' in tags:
            print(f"    \033[92m[✓] Bitsight Rule Pass: Aggregate reporting target published (rua={tags['rua']}).\033[0m")
        else:
            print("    \033[91m[✗] Bitsight Rule Violation: Missing 'rua' tag (DMARC runs blind without telemetry destination).")

    except Exception:
        print("    \033[91m[✗] DMARC Record: NOT FOUND or could not be resolved.\033[0m")


def get_rsa_key_size(p_tag_value):
    """Decodes the Base64 DER ASN.1 public key structure to extract the RSA bit length natively."""
    try:
        der_bytes = base64.b64decode(p_tag_value)
        idx = der_bytes.find(b'\x02\x82')
        if idx != -1:
            length = struct.unpack('>H', der_bytes[idx+2:idx+4])[0]
            if der_bytes[idx+4] == 0x00:
                length -= 1
            return length * 8
        elif der_bytes.find(b'\x02\x81') != -1:
            idx = der_bytes.find(b'\x02\x81')
            length = der_bytes[idx+2]
            if der_bytes[idx+3] == 0x00:
                length -= 1
            return length * 8
        return None
    except Exception:
        return None


def validate_dkim_content(record_text, selector_name):
    print(f"    \033[92m[✓] DKIM Record Found for '{selector_name}':\033[0m {record_text[:60]}...")
    
    tags = {}
    for part in record_text.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
            
    p_val = tags.get('p')
    if not p_val:
        print("    \033[91m[✗] Bitsight Rule Violation: Key is revoked or 'p=' tag is missing/empty.\033[0m")
        return True

    k_val = tags.get('k', 'rsa')
    if k_val != 'rsa':
        print(f"    \033[93m[!] Cryptography Note: Using non-RSA algorithm ({k_val}). Skipping bit length parsing.\033[0m")
        return True

    bit_size = get_rsa_key_size(p_val)
    if bit_size:
        print(f"        -> Detected RSA Key Strength: \033[1m{bit_size} bits\033[0m")
        if bit_size >= 2048:
            print(f"    \033[92m[✓] Bitsight Rule Pass: Robust Key Strength ({bit_size} bits >= 2048 bits).\033[0m")
        else:
            print(f"    \033[91m[✗] Bitsight Rule Violation: WEAK KEY ({bit_size} bits). Keys below 2048 bits degrade safety score.\033[0m")
    else:
        print("    \033[93m[!] Warning: Could not parse RSA public key structure to determine exact bit length.\033[0m")

    h_val = tags.get('h', '')
    if 'sha1' in h_val.lower() and 'sha256' not in h_val.lower():
        print("    \033[91m[✗] Bitsight Rule Violation: Explicitly restricted to insecure SHA-1 hash algorithms.\033[0m")
        
    return True


def check_dkim(domain, custom_selector=None, interactive=True):
    print("\n[*] Checking DKIM Record against BitSight Criteria...")
    common_selectors = ['default', 'google', 'k1', 'mail', 'sig1']
    found_any = False

    print("    [*] Brute-forcing common selectors...")
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if "v=DKIM1" in record_text or "p=" in record_text:
                    validate_dkim_content(record_text, selector)
                    found_any = True
                    break
        except Exception:
            continue
            
    if interactive and not custom_selector:
        print("\n    --- Manual DKIM Check ---")
        custom_selector = input("    Have a specific DKIM selector to check? (Leave empty to skip): ").strip()

    if custom_selector:
        dkim_domain = f"{custom_selector}._domainkey.{domain}"
        print(f"    [*] Querying record for selector: '{custom_selector}'...")
        try:
            txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
            custom_found = False
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if "v=DKIM1" in record_text or "p=" in record_text:
                    validate_dkim_content(record_text, custom_selector)
                    custom_found = True
                    found_any = True
                    break
            if not custom_found:
                print(f"    \033[91m[✗] Record found for selector '{custom_selector}', but it does not contain a valid public key format.\033[0m")
        except Exception as e:
            print(f"    \033[91m[✗] DKIM Selector '{custom_selector}' NOT FOUND or could not be resolved. ({e})\033[0m")

    if not found_any and not custom_selector:
        print("    \033[93m[!] DKIM Note: No active records discovered using standard common selectors.\033[0m")


def run(target, target_type=None, port=None, dkim_selector=None, interactive=True):
    if target_type == "IP Address":
        print("\n[!] Email security auditing (SPF/DKIM/DMARC) requires a Domain target, not an IP address.")
        return

    print("\n========================================")
    print(" E-MAIL SECURITY & BITSIGHT COMPLIANCE")
    print(f" Target: {target}")
    print("========================================")

    check_spf(target)
    check_dmarc(target)
    check_dkim(target, custom_selector=dkim_selector, interactive=interactive)