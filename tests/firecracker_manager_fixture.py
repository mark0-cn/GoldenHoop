"""Own the real foreground Rust installation service and observe native cleanup."""
import json
import os
import signal
from pathlib import Path
import subprocess
import time
import uuid


class Manager:
    def __init__(self, binary, config, cfg):
        self.binary, self.config, self.cfg = binary, config, cfg
        self.root = Path(cfg['data_root'])
        self.log = config.with_name(config.stem + '-manager.log')
        self.process = None
        self.owner = None
        self.stop_error = None
        self.deaths = []
        self.maintenance_restart = False

    def start(self):
        assert self.process is None or self.process.poll() is not None, 'do not replace a live owned manager'
        with self.log.open('ab') as output:
            self.process = subprocess.Popen([str(self.binary), 'manage', '--config', str(self.config)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        until = time.monotonic() + 60
        while True:
            marker = self.root / 'manager.json'
            if marker.exists():
                value = json.loads(marker.read_text())
                if value['ready'] and value['process']['pid'] == self.process.pid:
                    self.owner = value
                    break
            assert self.process.poll() is None and time.monotonic() < until, 'native manager did not become ready'
            time.sleep(.05)
        assert self.owner['process']['pid'] == self.process.pid
        assert self.owner['installation_id'] == self.cfg['installation_id']
        suffix = uuid.UUID(self.cfg['installation_id']).hex + '-' + uuid.UUID(self.owner['epoch']).hex
        assert self.owner['cgroup'] == '/sys/fs/cgroup/ghm-' + suffix
        group = Path(self.owner['cgroup'])
        expected_memory = (768 + (128 if self.cfg.get('checkpoints') or self.cfg.get('rootfs') else 0)) * 1024**2
        assert (group / 'memory.max').read_text().strip() == str(expected_memory)
        assert (group / 'pids.max').read_text().strip() == '32'
        for path, field in [(self.root/'manager.sock','socket_identity'), (group,'cgroup_identity')]:
            metadata = path.lstat()
            assert self.owner[field] == {'device':metadata.st_dev,'inode':metadata.st_ino}
        return self.owner

    def hard_kill(self):
        assert self.process and self.process.poll() is None
        assert self.owner['process']['pid'] == self.process.pid
        previous = self.owner
        self.process.kill()
        status = self.process.wait(timeout=15)
        assert status == -signal.SIGKILL
        proc = Path('/proc')/str(self.process.pid)
        assert not proc.exists(), 'the owned service parent must reap its killed manager'
        observed = {'owner':previous,'exit_status':status,'actual_process_absent':True,
                    'marker_retained':(self.root/'manager.json').exists(),
                    'socket_retained':(self.root/'manager.sock').exists(),
                    'cgroup_retained':Path(previous['cgroup']).exists()}
        assert observed['marker_retained']
        self.deaths.append(observed)
        return observed

    def observe(self, value):
        assert value['owner']['installation_id'] == self.cfg['installation_id']
        generation = uuid.UUID(value['owner']['generation'])
        suffix = uuid.UUID(self.cfg['installation_id']).hex + '-' + generation.hex
        paths = [self.root / 'vm' / generation.hex[:12],
                 Path('/sys/fs/cgroup') / ('ghv-' + suffix),
                 Path('/sys/fs/cgroup') / ('ghs-' + suffix)]
        result = {'paths': {str(path): path.exists() for path in paths}, 'processes': {}}
        for name in ['process', 'supervisor']:
            identity = value.get(name)
            if not identity:
                continue
            proc = Path('/proc') / str(identity['pid'])
            try:
                text = (proc / 'stat').read_text()
                parts = text.rsplit(')', 1)[1].split()
                same = int(parts[19]) == identity['start_ticks']
                observed = {'present': True, 'identity_start_matches': same,
                            'state': parts[0], 'parent_pid': int(parts[1])}
                if same:
                    for field in ['cgroup', 'wchan']:
                        try:
                            observed[field] = (proc / field).read_text()[:2048]
                        except FileNotFoundError:
                            pass
                result['processes'][name] = observed
            except FileNotFoundError:
                result['processes'][name] = {'present': False}
        if value.get('supervisor'):
            log = self.root / 'records' / (value['owner']['sandbox_id'] + '.supervisor.log')
            if log.exists():
                descriptor = os.open(log, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, 'rb') as source:
                    source.seek(max(0, os.fstat(source.fileno()).st_size - 16384))
                    result['supervisor_stderr_tail'] = source.read(16384).decode(errors='replace')
        return result

    def assert_parent(self, value):
        observed = self.observe(value)['processes']['supervisor']
        assert observed['identity_start_matches'] and observed['parent_pid'] == self.process.pid, observed

    def wait_collected(self, value, deadline, samples):
        assert value.get('process') and value.get('supervisor'), 'expiry requires both recorded process identities'
        started = time.monotonic()
        while True:
            observed = self.observe(value)
            state = {key: observed[key] for key in ['paths', 'processes']}
            if not samples or any(samples[-1][key] != state[key] for key in state):
                samples.append(dict(state, elapsed_seconds=round(time.monotonic() - started, 3)))
                del samples[:-64]
            processes = state['processes']
            assert time.monotonic() <= deadline, f'owned expiry collection deadline exceeded: {state}'
            if (not any(state['paths'].values()) and all(
                    name in processes and (not processes[name]['present']
                    or processes[name].get('identity_start_matches') is False)
                    for name in ['process', 'supervisor'])):
                return
            time.sleep(.2)

    def ensure_collection_owner(self):
        if self.process and self.process.poll() is not None and any(value['owner']['process']['pid']==self.process.pid for value in self.deaths):
            # Preserve the original failure and use the production restart/drain
            # path to collect this exact installation after an interrupted test.
            self.maintenance_restart = True
            self.start()

    def close(self):
        if not self.process:
            return
        self.ensure_collection_owner()
        if self.process.poll() is None:
            try:
                stopped = subprocess.run([str(self.binary), 'manager-stop', '--config', str(self.config)],
                                         capture_output=True, timeout=15)
                if stopped.returncode != 0:
                    raise RuntimeError(f'manager-stop exited with {stopped.returncode}: '
                                       + stopped.stderr.decode(errors='replace')[-2000:])
                assert json.loads(stopped.stdout) == {'stop_requested': True, 'cleanup': 'pending'}
            except (subprocess.TimeoutExpired, RuntimeError, ValueError, AssertionError) as error:
                self.stop_error = str(error) or 'manager-stop returned an invalid drain acknowledgement'
                # This Popen is the fixture's actual child. Graceful signal
                # drainage remains available when its IPC endpoint is broken.
                if self.process.poll() is None:
                    self.process.send_signal(signal.SIGTERM)
        status = self.process.wait(timeout=160)
        if status != 0:
            self.stop_error = self.stop_error or f'native manager exited with {status}'
        assert not (Path('/proc') / str(self.process.pid)).exists()
        if self.owner:
            assert not Path(self.owner['cgroup']).exists()
        assert not (self.root / 'manager.sock').exists()
        assert not (self.root / 'manager.json').exists()
        return self.stop_error

    def diagnostics(self):
        tail = ''
        if self.log.exists():
            with self.log.open('rb') as source:
                source.seek(max(0, self.log.stat().st_size - 5000))
                tail = source.read(5000).decode(errors='replace')
        return {'owner': self.owner, 'stderr_tail': tail, 'stop_error': self.stop_error,
                'actual_manager_deaths':self.deaths,'maintenance_restart':self.maintenance_restart,
                'process_collected': bool(self.process and self.process.poll() is not None
                                          and not (Path('/proc') / str(self.process.pid)).exists())}
