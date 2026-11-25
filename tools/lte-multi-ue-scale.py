#!/usr/bin/env python3
"""D10 multi-UE scale harness (local, isolated EPC). Starts the production
lte-ue in the d10ue namespace, waits for DRB, installs per-UE source policy
routing to the PDN test endpoint, and probes per-UE UL/DL traffic."""
import argparse, json, os, re, subprocess, sys, time, socket, struct, hashlib

def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)
def nsrun(ns, cmd, **kw): return run(["ip","netns","exec",ns]+cmd, **kw)

def mem_available_kb():
    for line in open('/proc/meminfo'):
        if line.startswith('MemAvailable:'): return int(line.split()[1])
    return 0

def netns_ip(ns, ip):
    out=nsrun(ns, ["ip","-br","addr"]).stdout
    for line in out.splitlines():
        parts=line.split()
        if len(parts)>=3 and parts[2].split('/')[0]==ip: return parts[0]
    return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--subs', required=True)
    ap.add_argument('--target', type=int, required=True)
    ap.add_argument('--start', type=int, default=3)
    ap.add_argument('--ns', default='d10ue')
    ap.add_argument('--ue', default='cmake-build-release/lte-ue')
    ap.add_argument('--dir', default='/tmp/d10/gen')
    ap.add_argument('--log', default='/tmp/d10/log')
    ap.add_argument('--epc-ns', default='d10epc')
    ap.add_argument('--test-ip', default='10.98.0.1')
    ap.add_argument('--uu-base', type=int, default=48000)
    ap.add_argument('--link-base', type=int, default=30000)
    ap.add_argument('--tun-base', default='d10u')
    ap.add_argument('--batch', type=int, default=4)
    ap.add_argument('--probe', default='cmake-build-release/lte-uu-traffic-probe')
    ap.add_argument('--probe-port', type=int, default=5611)
    ap.add_argument('--reserve-mb', type=int, default=512)
    ap.add_argument('--per-ue-mb', type=float, default=9.0)
    args=ap.parse_args()
    os.makedirs(args.dir, exist_ok=True); os.makedirs(args.log, exist_ok=True)
    subs=json.load(open(args.subs))
    if len(subs) < args.target: sys.exit(f"need {args.target} subscribers, have {len(subs)}")
    avail=mem_available_kb()/1024.0
    worst=args.per_ue_mb*args.target + args.reserve_mb
    print(f"MemAvailable={avail:.0f}MB estimated_need={worst:.0f}MB target={args.target}")
    if worst > avail:
        print("BLOCKED_RESOURCE_LIMIT: target would cross the declared MemAvailable reserve")
        sys.exit(3)
    procs={}
    def write_cfg(i):
        s=subs[i-1]
        cfg={'imsi':s['imsi'],'mcc':'460','mnc':'02','ueId':i,'k':s['k'],'opc':s['opc'],'amf':s['amf'],
             'initialSqn':'000000000000','pdnType':'IPv4','apn':s.get('apn','cmnet'),'networkCapability':'A020',
             'lifecycle':{'scenario':'attach-only','triggerAfterMs':600000,'procedureTimeoutMs':20000,'maxRetries':3,'pagingWaitMs':60000,'switchOff':False,'recoveryDelayMs':6000,'recoveryRetryMs':5000,'recoveryMaxAttempts':3},
             'enbLink':{'localAddress':'127.0.0.1','localPort':args.link_base+i,'address':'127.0.0.1','port':4998,'timeoutMs':15000},
             'uu':{'localAddress':'127.0.0.1','localPort':args.uu_base+i,'address':'127.0.0.1','port':47100},
             'tun':{'required':True,'namePrefix':f"{args.tun_base}{i:03d}",'mtu':1400,'routes':[]}}
        import yaml
        path=os.path.join(args.dir, f'ue{i}.yaml')
        with open(path,'w') as f: yaml.safe_dump(cfg,f,sort_keys=False)
        os.chmod(path,0o600); return path
    def start_one(i):
        path=write_cfg(i); log=os.path.join(args.log, f'ue{i}.log')
        f=open(log,'w')
        p=subprocess.Popen(["ip","netns","exec",args.ns,args.ue,"-c",path], stdout=f, stderr=subprocess.STDOUT)
        procs[i]=(p,f,log,None)
    def wait_one(i, timeout=40):
        p,f,log,ip=procs[i]
        deadline=time.time()+timeout
        while time.time()<deadline:
            if p.poll() is not None: return None
            try: t=open(log).read()
            except: t=''
            if 'DRB user plane configured' in t:
                m=re.search(r'IPv4=([0-9.]+)', t)
                if m:
                    ip=m.group(1); tun=netns_ip(args.ns, ip)
                    if tun:
                        nsrun(args.ns, ["ip","rule","del","from",ip,"lookup",str(10000+i),"priority",str(10000+i)])
                        nsrun(args.ns, ["ip","route","flush","table",str(10000+i)])
                        nsrun(args.ns, ["ip","rule","add","from",ip,"lookup",str(10000+i),"priority",str(10000+i)])
                        nsrun(args.ns, ["ip","route","add",args.test_ip+"/32","dev",tun,"table",str(10000+i)])
                        procs[i]=(p,f,log,ip); return ip
            if 'PROCEDURE_FAILED' in t or 'AUTHENTICATION_FAILED' in t or 'DRB configuration failed' in t:
                return None
            time.sleep(0.2)
        return None
    # probe server in the EPC namespace
    stop=os.path.join(args.log,'probe.stop'); srv_res=os.path.join(args.log,'probe-server.result')
    for x in (stop,srv_res):
        try: os.unlink(x)
        except FileNotFoundError: pass
    srv=subprocess.Popen(["ip","netns","exec",args.epc_ns,args.probe,"udp-echo-server","--bind",args.test_ip,
                          "--port",str(args.probe_port),"--result",srv_res,"--stop",stop],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    def probe_ips(ips, tag):
        ok=0; lost=0; details=[]
        for idx,ip in enumerate(ips):
            res=os.path.join(args.log, f'probe-{tag}-{idx}.result')
            r=nsrun(args.ns,[args.probe,"udp-client","--bind",ip,"--to",args.test_ip,"--port",str(args.probe_port),
                             "--count","5","--size","1372","--result",res])
            txt=open(res).read() if os.path.exists(res) else ''
            if 'result=COMPLETE' in txt and 'loss=0' in txt: ok+=1
            else: lost+=1; details.append((ip,txt.splitlines()[:3]))
        return ok,lost,details
    results=[]
    # staged targets: 4,8,16,32,64,128,256,512 (bounded by --target)
    stages=[s for s in [4,8,16,32,64,128,256,512] if s>=args.start and s<=args.target]
    if not stages or stages[-1]!=args.target: stages.append(args.target)
    done=args.start-1
    for target in stages:
        while done < target:
            batch=[j for j in range(done+1, min(target,done+args.batch)+1)]
            for j in batch: start_one(j)
            for j in batch:
                ip=wait_one(j)
                if ip is None:
                    print(f"FAIL ue{j}"); results.append((target,j,'FAIL',None)); 
                else:
                    done=max(done,j); print(f"ok ue{j} {ip}")
            time.sleep(0.05)
        active=[i for i in procs if procs[i][3]]
        ips=[procs[i][3] for i in active]
        ok,lost,details=probe_ips(ips, str(target))
        mme=nsrun(args.epc_ns,["curl","-s","--max-time","3","http://127.0.0.2:9090/metrics"]).stdout
        sess=re.search(r'^mme_session (\d+)',mme,re.M)
        print(f"STAGE {target}: active={len(active)} probe_ok={ok} probe_fail={lost} mme_session={sess.group(1) if sess else '?'} availMB={mem_available_kb()/1024:.0f}")
        results.append((target,len(active),ok,lost))
    print("RESULTS", results)
    try: open(stop,'w').close()
    except: pass
    time.sleep(0.5); srv.terminate()

if __name__=='__main__': main()
