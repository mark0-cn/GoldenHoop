"""Actual runsc images selected by public requests on one native profile.

Rust owns preparation, descriptor transfer, allocation, recovery and collection.
Python builds owned fixtures and checks independent runtime/storage observations.
"""
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tarfile
import time
import traceback
import uuid

from goldenhoop import ApiError, Client, Command
from firecracker_guest_contract import digest, run
from firecracker_manager_fixture import Manager


class Contract:
    def __init__(self, control, native, images, boot, fixture, source_base, builder, builder_owner):
        self.control, self.native, self.images = control, native, images
        self.boot, self.fixture = boot, fixture
        self.root, self.native_root, self.staging = fixture/'n', fixture/'v', fixture/'s'
        self.owns_root=False
        self.database, self.blobs = self.root/'state.db', self.root/'blobs'
        self.config = self.root/'native.json'
        self.source_base, self.builder = source_base, builder
        self.builder_owner=builder_owner
        self.owner = uuid.uuid4().hex
        self.labels = ['--label', 'dev.goldenhoop.task=m4-native-image-placement',
                       '--label', 'dev.goldenhoop.owner='+self.owner]
        self.processes, self.sources, self.jobs, self.parents, self.sandboxes = {}, [], [], [], []
        self.manager, self.client, self.mount_id = None, None, None
        self.token = uuid.uuid4().hex + uuid.uuid4().hex
        self.env = dict(os.environ, GOLDENHOOP_API_TOKEN=self.token,
                        DOCKER_HOST='unix:///var/run/docker.sock')
        self.report = dict(result='failed', cleanup='unknown', cases=[], observations={},
                           scope='public per-image native placement; snapshots/templates and full M4-M6 remain unaccepted')
    def initialize(self):
        assert not any(path.exists() for path in [self.root,self.native_root,self.staging])
        self.root.mkdir(mode=0o700);self.owns_root=True
        source_base,builder,builder_owner=self.source_base,self.builder,self.builder_owner
        base = json.loads(run(['docker','image','inspect',source_base]))[0]
        assert re.fullmatch(r'[a-z0-9][a-z0-9._/:-]{0,199}', source_base)
        self.base_id, self.base_layers = base['Id'], base['RootFS']['Layers']
        actual = json.loads(run(['docker','image','inspect',builder]))[0]
        assert actual['Config']['Labels']['dev.goldenhoop.owner'] == builder_owner
        assert actual['Config']['Labels']['dev.goldenhoop.task'] == 'm4-image-builder-fixture'
        self.builder = actual['Id']
        cid = run(['docker','create',*self.labels,'--network','none','--read-only','--cap-drop','ALL',
                   '--security-opt','no-new-privileges:true','--entrypoint','/bin/cat',self.builder,
                   '/opt/goldenhoop/inventory.json']).decode().strip()
        try:
            self.inventory = json.loads(run(['docker','start','--attach',cid]))
            observed=json.loads(run(['docker','inspect',cid]))[0]
            assert observed['State']['ExitCode']==0 and not observed['State']['OOMKilled']
        finally:
            self.remove_container(cid)

    def remove_container(self, cid):
        actual=json.loads(run(['docker','inspect',cid]))[0]
        assert actual['Config']['Labels']['dev.goldenhoop.owner']==self.owner
        assert actual['Config']['Labels']['dev.goldenhoop.task']=='m4-native-image-placement'
        run(['docker','rm','--force',cid])
        assert not run(['docker','ps','-aq','--filter','id='+cid]).strip()

    def events(self, name):
        path=self.root/(name+'.log')
        values=[]
        if path.exists():
            for line in path.read_text(errors='replace').splitlines():
                try: value=json.loads(line)
                except ValueError: continue
                if value.get('event')==name+'_started': values.append(value)
        return values

    def start(self, name):
        before=len(self.events(name))
        command=[str(self.control),'--database',str(self.database),name]
        if name=='api': command+=['--bind','127.0.0.1:0','--token',self.token]
        else: command+=['--runtime','firecracker','--firecracker-config',str(self.config),
                        '--artifact-root',str(self.blobs)]
        with (self.root/(name+'.log')).open('ab') as output:
            self.processes[name]=subprocess.Popen(command,stdin=subprocess.DEVNULL,
                stdout=output,stderr=subprocess.STDOUT,env=self.env)
        until=time.monotonic()+200
        while len(self.events(name))<=before:
            assert self.processes[name].poll() is None, f'{name} exited before readiness'
            assert time.monotonic()<until, f'{name} readiness deadline'
            time.sleep(.1)
        return self.events(name)[-1]

    def stop(self, name, hard=False):
        process=self.processes.get(name)
        if process and process.poll() is None:
            process.send_signal(signal.SIGKILL if hard else signal.SIGINT)
            process.wait(timeout=45)
        if process: assert not Path('/proc',str(process.pid)).exists()

    def image_call(self, arguments, expected=0):
        result=subprocess.run([str(self.images),'--database',str(self.database),'--artifact-root',
            str(self.blobs),*arguments],stdin=subprocess.DEVNULL,capture_output=True,timeout=360,
            env={'PATH':'/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8',
                 'DOCKER_HOST':'unix:///var/run/docker.sock'})
        assert result.returncode==expected, result.stderr.decode(errors='replace')[-3000:]
        return json.loads(result.stdout) if result.stdout.strip() else None

    def job(self, identity):
        with closing(sqlite3.connect(f'file:{self.database.as_posix()}?mode=ro',uri=True)) as connection:
            row=connection.execute('SELECT payload_json FROM image_jobs WHERE id=?',(identity,)).fetchone()
        return json.loads(row[0]) if row else None

    def source_image(self, marker):
        tag='goldenhoop-native-source:'+self.owner+'-'+marker.lower()
        context=io.BytesIO()
        with tarfile.open(fileobj=context,mode='w') as archive:
            for name,data in [('Dockerfile',f'FROM {self.source_base}\nCOPY sentinel /sentinel\nENTRYPOINT ["/source-never-started"]\n'.encode()),
                              ('sentinel',('GoldenHoop-image-'+marker+'\n').encode())]:
                entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o444
                archive.addfile(entry,io.BytesIO(data))
        run(['docker','build',*self.labels,'--tag',tag,'-'],timeout=180,input=context.getvalue())
        observed=json.loads(run(['docker','image','inspect',tag]))[0]
        assert observed['Config']['Labels']['dev.goldenhoop.owner']==self.owner
        assert observed['RootFS']['Layers'][:len(self.base_layers)]==self.base_layers
        assert json.loads(run(['docker','image','inspect',self.source_base]))[0]['Id']==self.base_id
        self.sources.append((tag,observed['Id']))
        return observed['Id']

    def prepare(self, source, pause=False):
        identity,generation=str(uuid.uuid4()),str(uuid.uuid4())
        self.jobs.append(identity)
        args=['prepare','--id',identity,'--generation',generation,'--source-image',source,
              '--builder-image',self.builder,'--disk-bytes',str(256*1024**2)]
        if not pause: return self.image_call(args)
        output=(self.root/'preparing.stdout').open('xb');error=(self.root/'preparing.stderr').open('xb')
        try:
            process=subprocess.Popen([str(self.images),'--database',str(self.database),'--artifact-root',str(self.blobs),*args],
                stdin=subprocess.DEVNULL,stdout=output,stderr=error,
                env={'PATH':'/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8',
                     'DOCKER_HOST':'unix:///var/run/docker.sock'})
        finally: output.close();error.close()
        self.parents.append(process)
        until=time.monotonic()+30
        while not self.job(identity):
            assert process.poll() is None and time.monotonic()<until
            time.sleep(.01)
        for attempt in range(3):
            process.send_signal(signal.SIGSTOP)
            until=time.monotonic()+5
            while Path('/proc',str(process.pid),'stat').read_text().rsplit(')',1)[1].split()[0]!='T':
                assert process.poll() is None and time.monotonic()<until
                time.sleep(.01)
            try:
                with closing(sqlite3.connect(self.database,timeout=.2)) as connection:
                    connection.execute('BEGIN IMMEDIATE');connection.rollback()
                break
            except sqlite3.OperationalError:
                process.send_signal(signal.SIGCONT);time.sleep(.03)
        else: raise AssertionError('producer cut held a SQLite writer; do not use that cut as image-only exclusion evidence')
        payload=self.job(identity)
        assert payload['phase']!='ready', 'unready producer cut missed; do not count a ready job as unready'
        self.report['observations']['actual_paused_producer']={'pid':process.pid,'generation':generation,
            'id':identity,'phase':payload['phase'],'state':'T','database_writer_quiescent':True}
        return identity,generation,process

    def info(self, preparation):
        assert preparation['image_ready'] and preparation['provider_cleanup']=='complete' and preparation['error'] is None
        value=self.image_call(['inspect-image','--id',preparation['id'],'--trusted-inventory',json.dumps(self.inventory)])
        reference=value['reference']
        expected=hashlib.sha256(json.dumps(value['manifest'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        assert expected==reference['manifest_sha256']
        return value,f'prepared:{reference["id"]}:{reference["generation"]}:{expected}'

    def spec(self, image):
        return {'profile':'local-firecracker','image':image,'ttl_seconds':600,
                'resources':{'cpu_millis':500,'memory_bytes':256*1024**2,'pids':40},
                'required_capabilities':['commands','files','pause','network_isolation']}

    def create(self, image, expected=None):
        created=self.client.create(self.spec(image),str(uuid.uuid4()));sid=created['sandbox']['id']
        self.sandboxes.append(sid)
        try:
            self.client.wait_operation(created['operation']['id'],timeout=150)
            assert expected is None, 'refused image unexpectedly started'
        except ApiError as error:
            assert expected is not None and error.code in expected, (error.code, str(error))
            assert not (self.native_root/'records'/f'{sid}.json').exists(), 'refusal allocated a native generation'
            self.report['observations'].setdefault('admission_refusals',[]).append({'sandbox':sid,'code':error.code})
        return sid

    def record(self, sid):
        return json.loads((self.native_root/'records'/f'{sid}.json').read_text())

    def check_guest(self, sid, marker):
        result=self.client.run(sid,Command(['python3','-c',
            "import os; from pathlib import Path; assert os.getuid()==1000; "
            "assert sorted(os.listdir('/sys/class/net'))==['lo']; "
            "assert 'GOLDENHOOP_API_TOKEN' not in os.environ and 'DOCKER_HOST' not in os.environ; "
            "print(Path('/sentinel').read_text(),end='')"]))
        assert result.stdout==('GoldenHoop-image-'+marker+'\n').encode() and not result.stderr
        assert result.execution['state']=='succeeded' and result.execution['exit_code']==0 and result.execution['cleanup']=='complete'

    def free_staging(self):
        until=time.monotonic()+10
        while os.statvfs(self.staging).f_bfree!=self.initial_free:
            assert time.monotonic()<until,'anonymous input still holds tmpfs blocks'
            time.sleep(.02)
        assert not list(self.staging.iterdir())

    def exercise(self):
        ready=self.start('api');installation=ready['installation_id']
        self.client=Client('http://'+ready['address'],self.token)
        self.staging.mkdir(mode=0o700)
        run(['mount','-t','tmpfs','-o','size=512m,mode=0700,nr_inodes=128',
             'goldenhoop-'+self.owner,str(self.staging)])
        mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==str(self.staging)]
        assert len(mounts)==1;self.mount_id=mounts[0][0]
        self.initial_free=os.statvfs(self.staging).f_bfree
        source_a,source_b=self.source_image('A'),self.source_image('B')
        prepared_a=self.prepare(source_a);info_a,image_a=self.info(prepared_a)
        cfg={'installation_id':installation,'data_root':str(self.native_root),'artifacts':self.boot,
             'supervisor':{'path':str(self.native),'sha256':digest(self.native),'size':self.native.stat().st_size},
             'image':'sha256:'+self.boot['rootfs']['sha256'],
             'prepared_images':{'inventory':self.inventory,'max_disk_bytes':256*1024**2,
                 'disk_budget_bytes':self.boot['rootfs']['size'],'staging_root':str(self.staging),
                 'staging_bytes':512*1024**2},
             'max_resources':{'cpu_millis':2000,'memory_bytes':512*1024**2,'pids':256},
             'capacity':{'cpu_millis':4000,'memory_bytes':6*1024**3,'max_vms':4},'max_ttl_seconds':600}
        self.config.write_text(json.dumps(cfg));self.config.chmod(0o600)
        self.manager=Manager(self.native,self.config,cfg);self.manager.start();self.start('worker')
        assert self.client.profiles()[0]['availability']=='available'
        first=self.create(image_a);self.check_guest(first,'A')
        identity,generation,parent=self.prepare(source_b,pause=True)
        try:
            self.create(f'prepared:{identity}:{generation}:{"0"*64}',expected={'invalid_request','not_found'})
            self.check_guest(first,'A')
            self.report['cases'].append('actual_unready_producer_refused_without_native_allocation_while_another_VM_remains_usable')
        finally:
            if parent.poll() is None: parent.send_signal(signal.SIGCONT)
        assert parent.wait(timeout=360)==0,(self.root/'preparing.stderr').read_text(errors='replace')[-3000:]
        assert not Path('/proc',str(parent.pid)).exists()
        prepared_b=json.loads((self.root/'preparing.stdout').read_bytes());info_b,image_b=self.info(prepared_b)
        second=self.create(image_b);self.check_guest(second,'B');self.check_guest(first,'A')
        records={sid:self.record(sid) for sid in [first,second]}
        for sid,info,image in [(first,info_a,image_a),(second,info_b,image_b)]:
            assert records[sid]['selected_image']==info
            assert self.client.sandbox(sid)['image']==image
            assert records[sid]['artifacts']['rootfs']['sha256']==info['manifest']['disk']['sha256']
            assert Path(records[sid]['artifacts']['rootfs']['path']).is_relative_to(self.native_root/'vm')
            self.client.write_file(sid,'identity',sid.encode())
        assert records[first]['owner']['generation']!=records[second]['owner']['generation']
        assert records[first]['process']['pid']!=records[second]['process']['pid']
        self.report['observations']['original_selected_generations']=records
        self.report['observations']['preparations']=[prepared_a,prepared_b]
        self.report['observations']['builder_image_id']=self.builder
        self.report['cases'].append('two_real_runsc_prepared_disks_selected_by_public_requests_on_one_profile_have_distinct_guest_markers_and_VM_identities')
        self.free_staging();self.report['cases'].append('both_successful_handoffs_release_actual_tmpfs_blocks_and_leave_no_named_input')
        self.create(image_a[:-64]+'0'*64,expected={'invalid_request'})
        self.create(cfg['image'],expected={'quota_exceeded'})
        self.check_guest(first,'A');self.check_guest(second,'B')
        self.report['cases'].append('changed_manifest_and_shared_fixed_selected_disk_budget_refuse_before_native_allocation')
        for prepared in [prepared_a,prepared_b]:
            collected=self.image_call(['collect-image','--id',prepared['id']])
            assert collected['phase']=='collected' and collected['provider_cleanup']=='complete'
            reference=prepared['disk']
            prefix=self.blobs/'goldenhoop'/reference['installation_id']/'large'/reference['id']/reference['generation']
            assert not (prefix/'manifest').exists() and not list(prefix.glob('chunk-*'))
        self.create(image_a,expected={'invalid_request'})
        self.check_guest(first,'A');self.check_guest(second,'B')
        self.report['cases'].append('actual_image_blob_collection_refuses_new_consumers_and_preserves_both_independent_live_VM_disks')
        self.client.wait_operation(self.client.pause(second,str(uuid.uuid4()))['id'],timeout=60)
        before=set((self.native_root/'records').glob('*.json'))
        self.stop('worker',hard=True);self.manager.hard_kill();self.manager.start();self.start('worker')
        assert self.client.profiles()[0]['availability']=='available'
        assert set((self.native_root/'records').glob('*.json'))==before,'recovery consumed an extra probe reservation'
        self.client.wait_operation(self.client.resume(second,str(uuid.uuid4()))['id'],timeout=60)
        for sid,marker in [(first,'A'),(second,'B')]:
            current=self.record(sid)
            for field in ['owner','process','supervisor','selected_image']:
                assert current[field]==records[sid][field],field
            assert self.client.read_file(sid,'identity')==sid.encode()
            self.check_guest(sid,marker)
        self.report['observations']['manager_recovery']=self.manager.diagnostics()
        self.report['cases'].append('actual_manager_and_worker_SIGKILL_recover_same_running_and_paused_selected_VMs_without_source_blobs_or_extra_probe_capacity')
        self.free_staging()
        self.report['result']='passed'

    def cleanup(self):
        errors=[]
        if not self.owns_root:
            self.report['cleanup']='complete';return
        for parent in self.parents:
            try:
                if parent.poll() is None:
                    parent.send_signal(signal.SIGCONT);parent.wait(timeout=360)
                assert not Path('/proc',str(parent.pid)).exists()
            except Exception as error: errors.append('image producer: '+str(error))
        try: self.stop('worker')
        except Exception as error: errors.append('worker: '+str(error))
        try:
            if self.manager:
                stopped=self.manager.close()
                if stopped: errors.append(stopped)
                observations=[]
                for path in (self.native_root/'records').glob('*.json'):
                    value=json.loads(path.read_text());observation=self.manager.observe(value)
                    assert value['phase']=='collected' and all(not present for present in observation['paths'].values())
                    assert all(not p.get('present') or not p.get('identity_start_matches') for p in observation['processes'].values())
                    observations.append(observation)
                self.report['observations']['final_native_absence']=observations
        except Exception as error: errors.append('native collection: '+str(error))
        for identity in self.jobs:
            try:
                payload=self.job(identity)
                if payload and payload['phase'] in ['ready','collecting']:
                    result=self.image_call(['collect-image','--id',identity]);assert result['provider_cleanup']=='complete'
                payload=self.job(identity)
                assert payload and payload['phase'] in ['collected','failed_collected'],payload
            except Exception as error: errors.append('image collection: '+str(error))
        try: self.stop('api')
        except Exception as error: errors.append('api: '+str(error))
        if self.client: self.client.close()
        try:
            for cid in run(['docker','ps','-aq','--filter','label=dev.goldenhoop.owner='+self.owner,
                            '--filter','label=dev.goldenhoop.task=m4-native-image-placement']).decode().splitlines():
                self.remove_container(cid)
        except Exception as error: errors.append('diagnostic fixture: '+str(error))
        for tag,identity in self.sources:
            try:
                actual=json.loads(run(['docker','image','inspect',tag]))[0]
                assert actual['Id']==identity and actual['Config']['Labels']['dev.goldenhoop.owner']==self.owner
                run(['docker','image','rm',tag]);assert not run(['docker','image','ls','-q','--filter','reference='+tag]).strip()
            except Exception as error: errors.append('source fixture: '+str(error))
        if self.mount_id:
            try:
                assert not errors, 'preserve mounted fixture while runtime collection is unconfirmed'
                self.free_staging()
                mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==str(self.staging)]
                assert len(mounts)==1 and mounts[0][0]==self.mount_id
                run(['umount',str(self.staging)])
                assert not any(line.split()[4]==str(self.staging) for line in Path('/proc/self/mountinfo').read_text().splitlines())
            except Exception as error: errors.append('scratch mount: '+str(error))
        if not errors:
            for path in [self.root,self.native_root,self.staging]:
                if path.exists():
                    assert path.parent==self.fixture and path.name in ['n','v','s'] and not path.is_symlink()
                    for entry in path.rglob('*'):
                        metadata=entry.lstat()
                        assert metadata.st_uid==0 and not stat.S_ISLNK(metadata.st_mode)
                        assert stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
                    shutil.rmtree(path);assert not path.exists()
            self.report['cleanup']='complete'
        else:
            self.report['cleanup_errors']=errors;self.report['result']='failed'


def suite(control,native,images,boot,fixture,source_base,builder,builder_owner):
    contract=None
    try:
        contract=Contract(control,native,images,boot,fixture,source_base,builder,builder_owner)
        contract.initialize()
        contract.exercise()
    except Exception as error:
        if contract is None: raise
        contract.report.update(result='failed',error=str(error),traceback=traceback.format_exc())
    finally:
        if contract:
            try: contract.cleanup()
            except Exception as error: contract.report.update(result='failed',cleanup='unknown',cleanup_error=str(error))
    return contract.report
