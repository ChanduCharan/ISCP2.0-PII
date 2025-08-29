import re
import json
import pandas as pd


PHONE_RE = re.compile(r'\b(?:\+91|91)?\D*([6-9]\d{9})\b')
IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PASSPORT_RE = re.compile(r'\b([A-Za-z]\d{7})\b')
UPI_RE = re.compile(r'\b([A-Za-z0-9._%+-]{2,256}@[\w]{2,50})\b')

def mask_phone(ph):
    s = re.sub(r'\D', '', str(ph))
    if len(s) == 10:
        return s[:2] + 'X'*(len(s)-4) + s[-2:]
    return '[REDACTED_PII]'

def mask_aadhar(a):
    s = re.sub(r'\D', '', str(a))
    if len(s) == 12:
        return s[:4] + 'X'*4 + s[-4:]
    return '[REDACTED_PII]'

def mask_passport(p):
    m = re.match(r'([A-Za-z])(\d{7})', str(p))
    if m:
        return m.group(1) + 'X'*5 + m.group(2)[-2:]
    return '[REDACTED_PII]'

def mask_email(e):
    m = re.match(r'([^@]+)@(.+)', str(e))
    if not m:
        return '[REDACTED_PII]'
    user, dom = m.group(1), m.group(2)
    if len(user) <= 2:
        user_masked = user[0] + 'X'*(len(user)-1)
    else:
        user_masked = user[:2] + 'X'*(len(user)-3) + user[-1]
    return user_masked + '@' + dom

def mask_upi(u):
    m = re.match(r'([^@]+)@(.+)', str(u))
    if not m:
        return '[REDACTED_PII]'
    user, dom = m.group(1), m.group(2)
    if len(user) <= 3:
        user_masked = 'X'*len(user)
    else:
        user_masked = user[:1] + 'X'*(len(user)-2) + user[-1]
    return user_masked + '@' + dom

def mask_name(name):
    parts = str(name).split()
    masked_parts = []
    for p in parts:
        if len(p) <= 1:
            masked_parts.append('X')
        elif len(p) == 2:
            masked_parts.append(p[0] + 'X')
        else:
            masked_parts.append(p[0] + 'X'*(len(p)-2) + p[-1])
    return ' '.join(masked_parts)

# Detection and Redaction
def detect_and_redact(obj):
    redacted = dict(obj)
    standalone = False
    combinatorial_count = 0

    # Standalone checks
    if 'phone' in obj and PHONE_RE.search(str(obj['phone'])):
        redacted['phone'] = mask_phone(obj['phone'])
        standalone = True
    if 'aadhar' in obj and len(re.sub(r'\D', '', str(obj['aadhar']))) == 12:
        redacted['aadhar'] = mask_aadhar(obj['aadhar'])
        standalone = True
    if 'passport' in obj and PASSPORT_RE.search(str(obj['passport'])):
        redacted['passport'] = mask_passport(obj['passport'])
        standalone = True
    if 'upi' in obj and UPI_RE.search(str(obj['upi'])):
        redacted['upi'] = mask_upi(obj['upi'])
        standalone = True

# Combinatorial checks
    name_present = False
    if 'name' in obj and len(str(obj['name']).split()) >= 2:
        redacted['name'] = mask_name(obj['name'])
        name_present = True

    email_present = False
    if 'email' in obj and EMAIL_RE.search(str(obj['email'])):
        redacted['email'] = mask_email(obj['email'])
        email_present = True

    addr_present = False
    if all(k in obj for k in ['address', 'city', 'pin_code']):
        redacted['address'] = '[REDACTED_PII]'
        redacted['city'] = '[REDACTED_PII]'
        redacted['pin_code'] = '[REDACTED_PII]'
        addr_present = True

    device_present = False
    if 'device_id' in obj:
        d = str(obj['device_id'])
        redacted['device_id'] = d[:3] + 'X'*(max(0,len(d)-5)) + d[-2:] if len(d) > 5 else '[REDACTED_PII]'
        device_present = True
    ip_present = False
    if 'ip_address' in obj and IPV4_RE.search(str(obj['ip_address'])):
        redacted['ip_address'] = '[REDACTED_PII]'
        ip_present = True

# combinatorial count
    if name_present: combinatorial_count += 1
    if email_present: combinatorial_count += 1
    if addr_present: combinatorial_count += 1
    if device_present or ip_present: combinatorial_count += 1

    is_pii = standalone or (combinatorial_count >= 2)
    return is_pii, redacted

def process(in_csv, out_csv):
    df = pd.read_csv(in_csv)
    rows = []
    for _, r in df.iterrows():
        rec_id = r.get('record_id', '')
        raw = r.get('data_json', '{}')
        try:
            obj = json.loads(raw)
        except Exception:
            obj = {}
        is_pii, redacted = detect_and_redact(obj)
        rows.append({
            'record_id': rec_id,
            'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
            'is_pii': is_pii
        })
    out = pd.DataFrame(rows)
    out.to_csv(out_csv, index=False)
    print(f"Wrote {out_csv}")

if __name__ == "__main__":
    import sys
    in_file = sys.argv[1] if len(sys.argv) > 1 else "iscp_pii_dataset.csv"
    out_file = "redacted_output_Chandrahas_Etikala.csv"
    process(in_file, out_file)