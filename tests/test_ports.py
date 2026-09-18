"""Isolated UFW/SSH command doubles: never touch the host firewall."""
import json
import pathlib
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'vpsfw.sh'

class PortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.rules = self.root/'rules'
        self.rules.write_text('')
        self.events = self.root/'events'
        self.events.touch()

    def run_script(self, body, ok=True, extra=''):
        code = 'source '+shlex.quote(str(SCRIPT))+'\n'
        code += 'TEST_ROOT='+shlex.quote(str(self.root))+'\n'
        code += r'''
ufw() {
    if [[ $* == 'show added' ]]; then cat "$TEST_ROOT/rules"; return; fi
    if [[ $1 == status ]]; then echo 'Status: active'; return; fi
    python3 - "$TEST_ROOT/events" "$@" <<'LOG'
import json,sys
with open(sys.argv[1],'a') as f: f.write(json.dumps(sys.argv[2:])+"\n")
LOG
    if [[ ${FAIL_UDP:-0} == 1 && $* == *udp* ]]; then return 1; fi
}
ssh_ports() { echo 34968; }
ss() { :; }
backup_ufw() { echo backup >> "$TEST_ROOT/events"; }
prune_backups() { echo prune >> "$TEST_ROOT/events"; }
session_port=34968
ssh_port=''
'''
        result = subprocess.run(['bash', '-c', code+'\n'+extra+'\n'+body], text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, ok, result.stdout+result.stderr)
        return result

    def commands(self):
        return [json.loads(l) for l in self.events.read_text().splitlines() if l.startswith('[')]

    def seed(self, port='443', proto='tcp', comment='VPS TCP', source='any'):
        if source == 'any': line=f'ufw allow {port}/{proto}'
        else: line=f'ufw allow from {source} to any port {port} proto {proto}'
        with self.rules.open('a') as f: f.write(line+' comment '+shlex.quote(comment)+'\n')

    def test_default_only_tcp(self):
        self.run_script('ports_command add 443')
        self.assertEqual(self.commands(), [['allow','443/tcp','comment','VPS TCP']])

    def test_multiport_range_and_source(self):
        self.run_script('ports_command add 443,8000:8010 both 192.0.2.0/24')
        commands=self.commands(); self.assertEqual(len(commands),4)
        self.assertIn(['allow','from','192.0.2.0/24','to','any','port','8000:8010','proto','udp','comment','VPS UDP'],commands)

    def test_ipv6_normalization(self):
        self.run_script('ports_command add 443 tcp 2001:0db8::1/128')
        self.assertEqual(self.commands()[0][2], '2001:db8::1')

    def test_delete_exact_source_only(self):
        self.seed(source='192.0.2.8')
        self.seed(source='198.51.100.8')
        self.run_script('ports_command delete 443 tcp 192.0.2.8')
        self.assertEqual(self.commands(), [['--force','delete','allow','from','192.0.2.8','to','any','port','443','proto','tcp']])

    def test_delete_requires_exact_range(self):
        self.seed(port='8000:8010')
        self.run_script('ports_command delete 8001',ok=False)
        self.assertEqual(self.events.read_text(),'')

    def test_change_adds_both_before_deleting(self):
        self.seed();self.seed(proto='udp',comment='VPS UDP')
        self.run_script('ports_command change 443 8443 both')
        c=self.commands()
        self.assertEqual([x[0] for x in c],['allow','allow','--force','--force'])
        self.assertEqual(c[0][1], '8443/tcp')

    def test_failed_change_preserves_old_rules(self):
        self.seed();self.seed(proto='udp',comment='VPS UDP')
        self.run_script('ports_command change 443 8443 both',ok=False,extra='FAIL_UDP=1')
        self.assertFalse(any(x[0]=='--force' for x in self.commands()))
        self.assertNotIn('prune',self.events.read_text())

    def test_other_protocol_does_not_block_add(self):
        self.seed(proto='udp',comment='DNS')
        self.run_script('ports_command add 443 tcp')
        self.assertEqual(len(self.commands()),1)

    def test_existing_rules_need_no_special_marker(self):
        self.seed(comment='existing service')
        self.run_script('ports_command add 443')
        self.assertEqual(self.commands(), [])
        self.run_script('ports_command delete 443')
        self.assertEqual(self.commands(),[['--force','delete','allow','443/tcp']])

    def test_existing_source_rule_can_be_deleted_directly(self):
        self.seed(port='8000:8010',source='192.0.2.0/24',comment='old app')
        self.run_script('ports_command delete 8000:8010 tcp 192.0.2.0/24')
        self.assertEqual(self.commands()[0],['--force','delete','allow','from','192.0.2.0/24','to','any','port','8000:8010','proto','tcp'])

    def test_ambiguous_matches_do_not_mutate(self):
        self.seed(); self.seed(comment='duplicate')
        self.run_script('ports_command add 443',ok=False)
        self.assertEqual(self.events.read_text(),'')

    def test_batch_prevalidated_before_any_change(self):
        self.seed()
        self.run_script('ports_command delete 443,8443',ok=False)
        self.assertEqual(self.events.read_text(),'')

    def test_ssh_range_and_new_ssh_port_protected(self):
        for command in ['ports_command add 34000:35000', 'ports_command delete 34968', 'ports_command change 443 34968']:
            self.seed()
            self.run_script(command,ok=False)
            self.assertEqual(self.events.read_text(),'')
            self.rules.write_text('')

    def test_udp_can_share_ssh_number(self):
        self.run_script('ports_command add 34968 udp')
        self.assertEqual(self.commands()[0][1],'34968/udp')

    def test_ssh_label_cannot_be_deleted(self):
        self.seed(port='2222',comment='SSH')
        self.run_script('ports_command delete 2222',ok=False)
        self.assertEqual(self.events.read_text(),'')

    def test_invalid_inputs_do_not_mutate(self):
        for command in ['ports_command add 65536', 'ports_command add 0', 'ports_command add 90:80',
                        'ports_command add 80,,443', 'ports_command add 443 icmp',
                        'ports_command add 443 tcp example.com', 'ports_command add 443 tcp 192.0.2.9/24',
                        'ports_command list extra', 'ports_command change 443 443']:
            self.run_script(command,ok=False)
            self.assertEqual(self.events.read_text(),'')

    def test_duplicate_input_deduplicated(self):
        self.run_script('ports_command add 443,443:443,443')
        self.assertEqual(len(self.commands()),1)

    def test_repeat_add_no_mutation(self):
        self.seed()
        self.run_script('ports_command add 443')
        self.assertEqual(self.commands(),[])

    def test_complex_rules_not_deleted(self):
        for line in ['ufw allow out 443/tcp', 'ufw route allow 443/tcp',
                     'ufw allow in on eth0 to any port 443 proto tcp',
                     'ufw allow proto tcp from any port 443 to any',
                     'ufw allow proto tcp from any to 192.0.2.3 port 443']:
            self.rules.write_text(line+'\n')
            self.run_script('ports_command delete 443',ok=False)
            self.assertEqual(self.events.read_text(),'')

    def test_full_syntax_permutations(self):
        for line in ['ufw allow proto tcp from 192.0.2.8 to any port 443',
                     'ufw allow in from 192.0.2.8 to any port 443 proto tcp']:
            self.rules.write_text(line+" comment 'VPS TCP'\n")
            self.run_script('ports_command delete 443 tcp 192.0.2.8')

    def test_list_includes_unmanaged_rules(self):
        self.seed(comment='old app')
        result=self.run_script('ports_command list')
        self.assertIn('old app',result.stdout)
        self.assertEqual(self.commands(),[])

if __name__=='__main__': unittest.main()
