"""Actual per-language state, failure, cancellation, deadline and UID collection."""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent_contract import docker, logs, source_fingerprint
from context_contract import ContextContract
from language_samples import LANGUAGES, SAMPLES, blocking


class LanguageContract(ContextContract):
    def __init__(self, image, runtime, language):
        super().__init__(image, runtime)
        self.language = language
        self.context_records=[]

    def new_context(self, wait=True):
        identity = str(uuid.uuid4())
        self.rpc({"method": "code_context_create", "id": identity, "spec": {"language": self.language}})
        if wait:
            record = self.wait_context(identity)
            assert record["spec"]["language"] == self.language, record
            assert record["kernel_info"]["language_info"]["name"] == self.language, record
            self.context_records.append(record)
        return identity

    def lifecycle(self):
        context = self.new_context()
        first, second, error = SAMPLES[self.language]
        run, request = self.start_code(context, first, timeout=30)
        self.rpc(request)
        result, events = self.wait_code(context, run, timeout=40)
        output=self.text(events)
        assert result["state"] == "kernel_succeeded" and output.endswith("kernel-start\n") and output.count("kernel-start\n")==1, (result, events)
        assert self.rpc(request)["value"] == result
        result, events = self.code(context, second)
        assert result["state"] == "kernel_succeeded" and self.text(events) == "42\n", (result, events)
        replay = self.rpc({"method":"read_file", "path":"lang-replay-"+self.language, "max_bytes":16})["value"]
        import base64
        assert base64.b64decode(replay["data_base64"]) == b"x", replay
        result, events = self.code(context, error)
        assert result["state"] == "kernel_failed" and result["kernel_status"] == "error", (result, events)
        assert self.context(context)["state"] == "ready"
        self.close(context)
        self.no_retired_context_processes_or_private_files()

    def stopping(self, timeout):
        context = self.new_context()
        if self.language=='go':
            # Loading a native dependency is separate from the timed workload.
            # Warm the blocker imports before requiring an escaped child marker.
            run,_=self.start_code(context,'import ("os/exec"; "time")',timeout=30)
            assert self.wait_code(context,run,timeout=40)[0]['state']=='kernel_succeeded'
        marker = self.language + ("-deadline" if timeout else "-cancel")
        run, _ = self.start_code(context, blocking(self.language, marker), timeout=10 if timeout else 60)
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            found = docker("exec", "--user", "0", self.container, "python3", "-I", "-c",
                f"from pathlib import Path; p=Path('/workspace/{marker}'); print(p.read_text() if p.exists() else '')")
            if found:
                assert int(found)>0
                break
            record = self.code_run(context, run)
            assert record["finished_at"] is None, record
            time.sleep(.05)
        else:
            raise AssertionError("escaped descendant did not start before cancellation/deadline")
        queued, _ = self.start_code(context, "queued_work_must_never_run")
        if not timeout:
            self.rpc({"method":"code_run_cancel", "context_id":context, "id":run})
        result, _ = self.wait_code(context, run, timeout=20)
        assert result["state"] == ("timed_out" if timeout else "cancelled"), result
        result, _ = self.wait_code(context, queued)
        assert result["state"] == "cancelled", result
        self.wait_context(context, "closed")
        self.no_retired_context_processes_or_private_files()


def run(args):
    root = Path(__file__).resolve().parents[1]
    evidence = {"suite":"agent-six-language-contract", "timestamp":datetime.now(timezone.utc).isoformat(),
        "runtime":args.runtime,"result":"failed","cleanup":"unknown","cases":[],"observations":[],
        "source_files_sha256":source_fingerprint()}
    for path in [Path(__file__).resolve(), root/'tests/language_samples.py', root/'tests/context_contract.py', *sorted((root/'images/languages').rglob('*'))]:
        if path.is_file(): evidence["source_files_sha256"][path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    failure = None
    clean = True
    for language in args.languages:
        fixture = LanguageContract(args.image,args.runtime,language)
        owned={'language':language,'attempt':fixture.attempt,'cleanup':'unknown'}
        evidence.setdefault('fixtures',[]).append(owned)
        try:
            fixture.start()
            owned['container_id']=fixture.container
            inspected = json.loads(docker('inspect', fixture.container))[0]
            evidence['image_id'] = inspected['Image']
            evidence['host_config'] = inspected['HostConfig']
            evidence['effective_mounts']=json.loads(docker('exec','--user','0',fixture.container,'python3','-I','-c',
                "import json; print(json.dumps({p[1]:p[3].split(',') for line in open('/proc/mounts') if (p:=line.split())[1] in ('/tmp','/workspace')}))"))
            assert inspected['HostConfig']['Runtime'] == args.runtime
            assert inspected['HostConfig']['NetworkMode'] == 'none' and inspected['HostConfig']['ReadonlyRootfs']
            assert inspected['HostConfig']['Memory']==1073741824 and inspected['HostConfig']['MemorySwap']==1073741824
            assert inspected['HostConfig']['PidsLimit']==256 and inspected['HostConfig']['NanoCpus']==1000000000
            for name, action in [('state_identity_replay_error_and_collection',fixture.lifecycle),
                    ('cancel_collects_escaped_descendant_and_queue',lambda:fixture.stopping(False)),
                    ('deadline_collects_escaped_descendant_and_queue',lambda:fixture.stopping(True))]:
                started=time.monotonic()
                action()
                evidence['cases'].append({'language':language,'case':name,'result':'passed','seconds':round(time.monotonic()-started,3)})
                print(json.dumps(evidence['cases'][-1]),flush=True)
        except BaseException as error:
            failure=failure or error
            evidence.setdefault('error',str(error))
            evidence.setdefault('failed_language',language)
            evidence.setdefault('failures',[]).append({'language':language,'error':str(error)})
            if fixture.container: evidence['logs']=logs(fixture.container)[-65536:]
        finally:
            evidence['observations'].extend(fixture.observations)
            evidence.setdefault('contexts',[]).extend(fixture.context_records)
            try:
                fixture.cleanup()
                assert not docker('ps','-aq','--filter','label=dev.goldenhoop.context-test='+fixture.attempt)
                owned['cleanup']='complete'
                owned['containers_absent']=True
            except BaseException as error:
                clean=False
                failure=failure or error
                evidence['cleanup_error']=str(error)
        if not clean: break
    evidence['cleanup']='complete' if clean else 'unknown'
    if not failure: evidence['result']='passed'
    evidence['docker']=json.loads(docker('version','--format','{{json .Server}}'))
    if args.runtime=='runsc': evidence['runsc_version']=subprocess.run(['runsc','--version'],check=True,capture_output=True,text=True).stdout.strip()
    if args.output:
        path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:evidence.get(k) for k in ('suite','result','cleanup','failed_language','error')}))
    if failure: raise failure


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',default='goldenhoop-languages-fixture:test')
    parser.add_argument('--runtime',choices=['runc','runsc'],default='runc')
    parser.add_argument('--languages',nargs='+',choices=LANGUAGES,default=LANGUAGES)
    parser.add_argument('--output')
    run(parser.parse_args())
