"""Build and run an explicitly ignored Rust test on actual owned cgroups.

No cgroup operation is implemented here. The ordinary workspace suite excludes
this test; only a dedicated root/writable-cgroup release gate may accept it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TEST = 'machine::cgroup_tests::actual_owned_cgroup_receipts_and_drop_preserve_replacement_process'
MARKER = 'GH_CGROUP_RECEIPT_CONTRACT='


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def inputs():
    paths = [ROOT/'Cargo.toml', ROOT/'Cargo.lock']
    paths += sorted(p for p in (ROOT/'crates').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    return {p.relative_to(ROOT).as_posix():digest(p) for p in paths}


def build(destination, owner):
    assert re.fullmatch(r'[0-9]+-[0-9]+', owner)
    assert destination == ROOT/f'.goldenhoop-cgroup-test-{owner}.json' and not destination.exists()
    before = inputs()
    command = ['cargo','test','--locked','--release','-p','goldenhoop-firecracker','--lib','--no-run','--message-format=json']
    sources = dict(before)
    for name in ['tests/firecracker_cgroup_contract.py','.github/workflows/firecracker-cgroup-receipts.yml']:
        sources[name]=digest(ROOT/name)
    report = {'suite':'source-fenced release cgroup test compilation','source_commit':os.environ['GITHUB_SHA'],
              'source_files_sha256':sources,'result':'failed','cleanup':'not_applicable','cases':[],
              'runtime_started':False,'scope':'compilation and executable discovery only; no actual cgroup or KVM result',
              'build_command':command}
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
        report['build_output_sha256']=hashlib.sha256(result.stdout+result.stderr).hexdigest()
        artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b'{')]
        candidates = [v for v in artifacts if v.get('reason')=='compiler-artifact'
                      and v['target']['name']=='goldenhoop_firecracker' and v['profile']['test'] and v.get('executable')]
        assert len(candidates)==1 and inputs()==before
        artifact = candidates[0]
        metadata = json.loads(subprocess.check_output(['cargo','metadata','--locked','--no-deps','--format-version','1'],cwd=ROOT))
        assert metadata['version']==1 and Path(metadata['workspace_root']).resolve()==ROOT
        packages = [p for p in metadata['packages'] if Path(p['manifest_path']).resolve()==ROOT/'crates/firecracker/Cargo.toml']
        assert len(packages)==1 and artifact['package_id']==packages[0]['id']
        assert Path(artifact['manifest_path']).resolve()==ROOT/'crates/firecracker/Cargo.toml'
        assert Path(artifact['target']['src_path']).resolve()==ROOT/'crates/firecracker/src/lib.rs'
        assert 'lib' in artifact['target']['kind'] and artifact['profile']['debug_assertions'] and artifact['profile']['overflow_checks']
        binary = Path(artifact['executable']).resolve(strict=True)
        report['artifact_executable']=str(binary)
        # Cargo's internal layout changed in 1.100. Use its actual artifact and
        # configured roots; a deps/ subdirectory is not a stable interface.
        locations = [Path(metadata[k]).resolve() for k in ['target_directory','build_directory'] if k in metadata]
        assert all(p.is_relative_to(ROOT/'target') for p in locations)
        assert any(binary.is_relative_to(p) for p in locations) and binary.is_file()
        assert any(Path(name).resolve(strict=True)==binary for name in artifact['filenames'])
        assert all(digest(ROOT/name)==sha for name,sha in sources.items()), 'build source inputs changed'
        manifest = {'format':1,'owner':owner,'binary':binary.relative_to(ROOT).as_posix(),
                    'binary_sha256':digest(binary),'binary_size':binary.stat().st_size,
                    'source_files_sha256':before,'build_command':command,
                    'build_output_sha256':report['build_output_sha256'],'test':TEST}
        with destination.open('x',encoding='utf-8',newline='\n') as output:
            output.write(json.dumps(manifest,indent=2)+'\n')
        report['result']='passed';report['binary_sha256']=manifest['binary_sha256']
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
        if isinstance(error,subprocess.CalledProcessError):
            raw=(error.stdout or b'')+(error.stderr or b'')
            report['build_output_sha256']=hashlib.sha256(raw).hexdigest()
            report['diagnostic_tail']=raw.decode(errors='replace')[-8000:]
        raise
    finally:
        report['source_changed_during_run']=any(digest(ROOT/name)!=sha for name,sha in sources.items())
        if report['source_changed_during_run']:
            report['result']='failed'
        directory=ROOT/'evidence';directory.mkdir(exist_ok=True)
        with (directory/'firecracker-cgroup-build.json').open('x',encoding='utf-8',newline='\n') as output:
            output.write(json.dumps(report,indent=2)+'\n')
        assert not report['source_changed_during_run'], 'build source inputs changed'
    print(json.dumps({'test_build_manifest':destination.name,'compiled_inputs':len(before),
                      'binary_sha256':manifest['binary_sha256']}),flush=True)


def suite(manifest_path, fixture, owner):
    report = {'result':'failed','cleanup':'unknown','cases':[],'host_uid':os.geteuid(),
              'scope':'actual Rust cgroup receipt/open/kill/reap/replacement/Drop checks; no VM-root allocation recovery claim'}
    try:
        assert os.geteuid()==0
        manifest = json.loads(manifest_path.read_bytes())
        assert manifest['format']==1 and manifest['owner']==owner and manifest['test']==TEST
        assert manifest['source_files_sha256']==inputs(), 'compiled test inputs differ'
        source = (ROOT/manifest['binary']).resolve(strict=True)
        assert source.is_relative_to(ROOT/'target') and source.is_file()
        assert source.stat().st_size==manifest['binary_size'] and digest(source)==manifest['binary_sha256']
        binary = fixture/'owned-cgroup-contract'
        shutil.copyfile(source,binary); binary.chmod(0o500)
        assert digest(binary)==manifest['binary_sha256']
        report['binary_sha256']=manifest['binary_sha256']
        report['compiled_inputs_verified']=len(manifest['source_files_sha256'])
        process = subprocess.run([str(binary),'--ignored','--exact',TEST,'--nocapture','--test-threads=1'],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=60,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        report['exit_code']=process.returncode
        report['output_sha256']=hashlib.sha256(process.stdout+process.stderr).hexdigest()
        report['stderr_tail']=process.stderr.decode(errors='replace')[-3000:]
        matches = [line.split(MARKER,1)[1] for line in process.stdout.decode().splitlines() if MARKER in line]
        assert len(matches)==1, process.stdout.decode(errors='replace')[-6000:]
        observed = json.loads(matches[0]); report['observed']=observed
        report['cases']=observed['cases']
        assert observed['cleanup']=='complete'
        # Independently sample the exact original group and replacement process.
        group = Path(observed['observations']['group'])
        assert group.parent==Path('/sys/fs/cgroup') and group.name.startswith('gh-receipt-')
        assert not group.exists()
        previous = observed['observations']['replacement_process']
        try:
            start = int((Path('/proc')/str(previous['pid'])/'stat').read_text().rsplit(')',1)[1].split()[19])
        except FileNotFoundError:
            start = None
        assert start != previous['start_ticks']
        report['independent_group_and_original_process_absence']=True
        report['cleanup']='complete'
        assert process.returncode==0 and observed['result']=='passed'
        assert len(observed['cases'])==4 and observed['observations']['replacement_alive_after_machine_drop']
        report['result']='passed'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--build-output',required=True,type=Path)
    parser.add_argument('--owner',required=True)
    args=parser.parse_args()
    build(args.build_output.resolve(),args.owner)
