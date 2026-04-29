# modules/sanitize.py
# WRAITH prompt injection defense
import re, html
RED='\033[31m';DIM='\033[2m';RESET='\033[0m'
INJECT_PATTERNS=[
    r'ignore\s+previous\s+instructions',
    r'you\s+are\s+now',
    r'system\s+prompt',
    r'repeat\s+after\s+me',
    r'output\s+your\s+instructions',
    r'disregard\s+all',
    r'forget\s+everything',
    r'new\s+persona',
    r'act\s+as\s+',
    r'jailbreak',
    r'DAN\s+mode',
    r'~/\.wraith',
    r'keys\.py',
    r'auth\.cfg',
]
def clean_wire_value(value, field="unknown"):
    if not isinstance(value, str): return value
    value=html.escape(value)
    value=re.sub(r'[\x00-\x1f\x7f]','',value)
    value=value[:512]
    for pattern in INJECT_PATTERNS:
        if re.search(pattern,value,re.IGNORECASE):
            print(f"  {RED}[SANITIZE] injection attempt in {field}{RESET}")
            return f"[SANITIZED:{field}]"
    return value
def clean_dict(d, context=""):
    if not isinstance(d,dict): return d
    return {k:clean_wire_value(str(v),f"{context}.{k}")
            if isinstance(v,str) else v
            for k,v in d.items()}
def scan_filestack_value(value, field=""):
    if not isinstance(value,str): return value,False
    for pattern in INJECT_PATTERNS:
        if re.search(pattern,value,re.IGNORECASE):
            return f"[BLOCKED:{field}]",True
    return value,False
def sanitize_filestack(data, context=""):
    if isinstance(data,dict):
        clean={}
        for k,v in data.items():
            if isinstance(v,str):
                sv,hit=scan_filestack_value(v,f"{context}.{k}")
                clean[k]=sv
            elif isinstance(v,dict):
                clean[k]=sanitize_filestack(v,f"{context}.{k}")
            elif isinstance(v,list):
                clean[k]=[sanitize_filestack(i,f"{context}.{k}")
                          if isinstance(i,dict) else i for i in v]
            else:
                clean[k]=v
        return clean
    return data
def validate_doxa_output(response):
    warnings=[]
    patterns=[
        (r'sk-ant-[a-zA-Z0-9]+','API key pattern'),
        (r'~\/\.wraith','key directory path'),
        (r'keys\.py','keys file reference'),
        (r'auth\.cfg','auth file reference'),
        (r'password[:\s]+\S+','credential pattern'),
    ]
    for pattern,msg in patterns:
        if re.search(pattern,response,re.IGNORECASE):
            warnings.append(msg)
    return warnings
