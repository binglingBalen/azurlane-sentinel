"""Continuous cloud sampling; scheduled Actions only provide restart insurance."""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent


def command(args,timeout=90):
    result=subprocess.run(args,cwd=ROOT,text=True,encoding='utf-8',errors='replace',
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    if result.returncode:
        raise RuntimeError(str(args[:3])+': '+result.stdout[-500:])
    return result.stdout


def publish():
    command(['git','add','--','state.json','task.json'])
    diff=subprocess.run(['git','diff','--cached','--quiet'],cwd=ROOT)
    if diff.returncode==0:return
    if diff.returncode!=1:raise RuntimeError('Cannot inspect staged cloud state')
    command(['git','-c','user.name=github-actions[bot]','-c',
             'user.email=41898282+github-actions[bot]@users.noreply.github.com',
             'commit','-m','sentinel: content observation and task delivery'])
    for attempt in range(3):
        try:
            command(['git','push']);return
        except RuntimeError:
            if attempt==2:raise
            command(['git','pull','--rebase','--autostash'])


def successor():
    token=os.environ.get('GITHUB_TOKEN');repo=os.environ.get('GITHUB_REPOSITORY')
    if not token or not repo:return False
    body=json.dumps(dict(ref=os.environ.get('GITHUB_REF_NAME','main'),
                         inputs=dict(verify_delivery=False))).encode()
    request=urllib.request.Request('https://api.github.com/repos/'+repo+
        '/actions/workflows/probe.yml/dispatches',data=body,method='POST',
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                 'Content-Type':'application/json','User-Agent':'alz-sentinel-watch'})
    with urllib.request.urlopen(request,timeout=30) as response:return response.status==204


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interval',type=int,default=60)
    parser.add_argument('--duration',type=int,default=18000)
    parser.add_argument('--verify-delivery',action='store_true')
    args=parser.parse_args();deadline=time.monotonic()+min(args.duration,18000)
    if not 120<=args.duration<=18000:parser.error('duration must be 120..18000 seconds')
    first=True;failures=0
    try:
        while time.monotonic()<deadline:
            started=time.monotonic()
            try:
                command(['git','pull','--rebase','--autostash','--quiet'])
                invocation=[sys.executable,'-u','probe.py','--no-mail']
                if first and args.verify_delivery:invocation.append('--verify-delivery')
                result=subprocess.run(invocation,cwd=ROOT,timeout=100)
                if result.returncode:raise RuntimeError('Cloud content probe returned '+str(result.returncode))
                publish();failures=0;first=False
                print('Cloud sample and task publication complete',flush=True)
            except Exception as error:
                failures+=1;print('Cloud sample failed: '+type(error).__name__+': '+str(error),flush=True)
                if failures>=5:raise
            delay=max(1,max(30,args.interval)-(time.monotonic()-started))
            time.sleep(min(delay,max(0,deadline-time.monotonic())))
    finally:print('Successor dispatched: '+str(successor()),flush=True)


if __name__=='__main__':main()
