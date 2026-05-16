import os, json
from datetime import datetime
from modules.core.asset_registry import all_records, upsert as reg_upsert
from modules.core.filestack import write_json
from modules.core.alerts import fire

_now = lambda: datetime.utcnow().isoformat()+'Z'

KNOWN_DEFAULTS = {
    80:   [('HTTP','admin','admin'),('HTTP','admin','password'),('HTTP','admin','')],
    443:  [('HTTPS','admin','admin'),('HTTPS','admin','password')],
    8080: [('HTTP-ALT','admin','admin'),('HTTP-ALT','admin','1234')],
    8001: [('SAMSUNG-API','',''),('SAMSUNG-API','admin','samsung')],
    9080: [('SAMSUNG-TV','',''),('SAMSUNG-TV','admin','')],
    23:   [('TELNET','admin','admin'),('TELNET','root','root'),('TELNET','','')],
    21:   [('FTP','anonymous',''),('FTP','admin','admin')],
    161:  [('SNMP','public',''),('SNMP','private','')],
    502:  [('MODBUS','','')],
    47808:[('BACNET','','')],
    1883: [('MQTT','',''),('MQTT','admin','admin')],
    102:  [('S7COMM','','')],
    44818:[('ETHERNET-IP','','')],
    4840: [('OPC-UA','','')],
    22:   [('SSH','admin','admin'),('SSH','root','root'),('SSH','admin','')],
    3389: [('RDP','administrator',''),('RDP','admin','admin')],
}

OT_RISK = {502,47808,102,44818,4840,20000}
HIGH_RISK = {23,21,161}

def run_credential_exposure():
    C='\033[36m';R='\033[31m';Y='\033[33m';G='\033[32m'
    D='\033[2m';B='\033[1m';RS='\033[0m'
    print(f"\n{C}  [CREDS] default credential exposure analysis{RS}")
    recs = all_records()
    findings = []
    for rec in recs:
        ip = rec['network']['ip']
        ports = rec['network']['open_ports']
        if not ports: continue
        host_findings = []
        for port in ports:
            if port not in KNOWN_DEFAULTS: continue
            creds = KNOWN_DEFAULTS[port]
            svc = creds[0][0]
            risk = 'CRITICAL' if port in OT_RISK else 'HIGH' if port in HIGH_RISK else 'MEDIUM'
            color = R if risk in ('CRITICAL','HIGH') else Y
            for svc_name,user,pwd in creds:
                entry = {'ip':ip,'port':port,'service':svc_name,'username':user,'password':pwd,'risk':risk}
                host_findings.append(entry)
            cred_str = ', '.join([f"{u}/{p}" if u else 'no-auth' for s,u,p in creds[:2]])
            print(f"  {color}{B}[{risk}]{RS} {C}{ip}{RS}:{port} {svc} — defaults: {cred_str}")
            if risk in ('CRITICAL','HIGH'):
                fire('DEFAULT_CRED_RISK',f"{ip}:{port} {svc} has known default credentials",severity=risk,source='credential_exposure',ip=ip)
        if host_findings:
            findings.extend(host_findings)
            ioc = [f"DEFAULT_CRED:{f['port']}" for f in host_findings]
            reg_upsert(ip=ip,mac='',source='credential_exposure',**{'threat.ioc_flags':ioc})
    write_json('credential_findings.json',{'timestamp':_now(),'count':len(findings),'findings':findings})
    print(f"\n  {G}[CREDS]{RS} {len(findings)} exposures — credential_findings.json written")
    return findings
