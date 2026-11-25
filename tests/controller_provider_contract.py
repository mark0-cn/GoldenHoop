"""Actual Rust-owned controller create, private stdio, exit and collection."""
import argparse
import hashlib
import json
from pathlib import Path

from native_bridge_contract import Contract as NativeContract


class Contract(NativeContract):
    def __init__(self, args):
        super().__init__(args)
        self.controller_image_id = None
        self.report['suite'] = 'rust-owned-controller-provider'
        self.report['scope'] = 'Actual native checkpoint, pinned controller placement, private stdio and provider collection; no production controller journal or workload/packet publication'
        self.report['source_files_sha256']['tests/controller_provider_contract.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def invoke(self, action, *extra, expected=0):
        if action.startswith('controller-'):
            assert self.controller_image_id
            extra = ('--controller-image', self.controller_image_id, *extra)
        try:
            return super().invoke(action, *extra, expected=expected)
        except BaseException:
            if action == 'controller-create' and self.report['invocations'][-1]['timed_out']:
                self.creation_uncertain = True
                self.settled = False
            raise

    def owned(self, obj):
        labels = obj.get('Labels', obj.get('Config', {}).get('Labels', {}))
        if labels.get('dev.goldenhoop.role') != 'egress-controller':
            return super().owned(obj)
        assert labels['dev.goldenhoop.installation'] == self.installation
        assert labels['dev.goldenhoop.sandbox'] == self.sandbox
        assert labels['dev.goldenhoop.profile'] == self.plan['identity']['profile']
        native = self.report['native_checkpoint_recovered_from_file_database']['native']['allocation']
        plan = json.loads(labels['dev.goldenhoop.controller-plan'])
        assert plan == {'native': {'identity': self.plan['identity'], 'allocation': native,
                                  'provisioning_token': self.plan['provisioning_token'],
                                  'expires_at': self.plan['expires_at']}, 'image_id': self.controller_image_id}
        assert obj['Config']['Image'] == obj['Image'] == self.controller_image_id
        assert obj['Name'] == '/goldenhoop-egress-'+self.plan['identity']['generation'].replace('-', '')
        return labels

    def controller_inspection(self):
        name = 'goldenhoop-egress-'+self.plan['identity']['generation'].replace('-', '')
        ids = self.docker('ps', '-a', '--no-trunc', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}').stdout.split()
        assert len(ids) == 1
        actual = json.loads(self.docker('inspect', ids[0]).stdout)[0]
        self.owned(actual)
        return actual

    def binding_checks(self):
        super().binding_checks()
        image = json.loads(self.docker('image', 'inspect', self.args.controller_image).stdout)[0]
        assert image['Config']['Labels']['dev.goldenhoop.egress'] == 'host-netfilter'
        self.controller_image_id = image['Id']
        self.report['controller_image_id'] = image['Id']
        self.save()
        self.invoke('controller-create', '--fault-after-controller', expected=77)
        created = self.controller_inspection()
        assert created['State']['Status'] == 'created' and not created['State']['Running']
        self.report['actual_controller_created_inspection'] = created
        self.check('actual_rust_process_exit_after_owned_controller_creation_preserves_the_original_unstarted_instance')
        recovered = self.invoke('controller-recover')
        assert recovered['controller']['container_id'] == created['Id']
        assert recovered['controller']['status'] == 'created'
        assert not recovered['creation_replayed'] and not recovered['start_replayed']
        assert self.controller_inspection()['Created'] == created['Created']
        self.check('fresh_rust_lookup_recovers_the_original_pinned_controller_without_creation_or_start_replay')
        host = created['HostConfig']; config = created['Config']
        assert host['NetworkMode'] == 'host' and host['Runtime'] == 'runc'
        assert host['ReadonlyRootfs'] and not host['Privileged']
        assert host['CapDrop'] == ['ALL'] and host['CapAdd'] == ['NET_ADMIN']
        assert host['SecurityOpt'] == ['no-new-privileges:true']
        assert not host['Binds'] and not created['Mounts'] and not host['PidMode']
        assert host['IpcMode'] == 'private' and host['CgroupnsMode'] == 'private'
        assert host['Memory'] == host['MemorySwap'] == 128*1024*1024
        assert host['NanoCpus'] == 250_000_000 and host['PidsLimit'] == 32
        assert config['User'] == '0:0' and config['OpenStdin'] and config['StdinOnce'] and not config['Tty']
        assert config['Env'] == ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
        assert host['LogConfig']['Type'] == 'none' and not host['AutoRemove'] and host['RestartPolicy']['Name'] == 'no'
        self.check('independent_docker_inspection_confirms_pinned_host_placement_single_capability_private_namespaces_and_no_host_mounts_or_credentials')
        # The previous native-only checks have closed every manager. Clear only
        # this owned empty bridge's fixture alias so the Rust Docker transport
        # must perform and confirm the actual native write itself.
        self.fixture_alias('')
        assert not self.link().get('ifalias')
        result = self.invoke('controller-run')
        assert result['exchange']['native_alias']['changed']
        assert result['exchange']['native_alias']['allocation'] == self.report['actual_alias_binding']['plan']['allocation']
        assert not result['exchange']['manager']['installed'] and result['exchange']['manager']['revision'] is None
        assert result['exchange']['expired_local_call_did_not_fence_channel']
        assert len(result['exchange']['foreign_refusals']) == 4 and result['exchange']['duplicate_create_start_refused']
        self.report['actual_rust_controller_exchange'] = result
        self.check('rust_private_stdio_binds_the_journaled_native_identity_and_opens_the_manager_without_packet_or_workload_publication')
        self.check('foreign_plan_and_container_ids_local_deadlines_duplicate_creation_and_duplicate_start_refuse_before_widening_authority')
        exited = self.controller_inspection()
        assert exited['Id'] == created['Id'] and exited['State']['Status'] == 'exited'
        assert not exited['State']['Running'] and exited['State']['ExitCode'] == 0
        assert result['exited']['container_id'] == created['Id'] and result['exited_controller_not_restarted']
        self.report['actual_controller_exited_inspection'] = exited
        self.check('private_channel_close_requires_independently_observed_successful_process_exit_and_exited_controllers_never_restart')
        collected = self.invoke('controller-collect')
        assert collected['removed']['container_id'] == created['Id']
        assert collected['removed']['provider_absent'] and collected['repeated_collection']['provider_absent']
        assert not collected['native_collection_attested']
        assert not self.docker('ps', '-a', '--no-trunc', '--filter', 'id='+created['Id'], '--format', '{{.ID}}').stdout.strip()
        assert self.link()['ifalias'] == self.report['actual_alias_binding']['reply']['alias']
        assert not self.audit()['owned_tables']
        self.check('rust_controller_collection_and_replay_confirm_provider_absence_without_claiming_native_bridge_or_table_collection')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--image', default='goldenhoop-network-fixture:test')
    parser.add_argument('--agent-image', default='goldenhoop-agent:test')
    parser.add_argument('--controller-image', default='goldenhoop-egress:test')
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--remove-image', action='store_true')
    parser.add_argument('--fail-after-create', action='store_true')
    Contract(parser.parse_args()).run()
