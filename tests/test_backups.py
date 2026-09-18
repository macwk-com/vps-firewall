"""Exercise retention in temporary directories, never on real /var/backups."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT=pathlib.Path(__file__).resolve().parents[1]/'vpsfw.sh'
CODE=SCRIPT.read_text().split("<<'PYBACKUP'",1)[1].split('\n',1)[1].split('\nPYBACKUP',1)[0]

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
        self.pending=self.root/'pending'
    def backup(self,name):
        p=self.root/name;p.mkdir();(p/'ufw').mkdir();(p/'ufw-default').touch();return p
    def run_policy(self,current,success=True):
        r=subprocess.run([sys.executable,'-c',CODE,str(current),str(self.root),str(self.pending)],capture_output=True,text=True)
        self.assertEqual(r.returncode==0,success,r.stderr)
    def test_keeps_current_and_ignores_unrelated(self):
        old=self.backup('vps-security.AAAAAAAA');new=self.backup('vps-security.BBBBBBBB')
        unrelated=self.backup('other-backup');unknown=self.root/'vps-security.CCCCCCCC';unknown.mkdir()
        self.run_policy(new)
        self.assertFalse(old.exists());self.assertTrue(new.exists());self.assertTrue(unrelated.exists());self.assertTrue(unknown.exists())
    def test_pending_migration_is_pinned(self):
        old=self.backup('vps-security-ssh.AAAAAAAA');new=self.backup('vps-security.BBBBBBBB')
        self.pending.write_text(str(old)+'\n2222\n38217\n')
        self.run_policy(new);self.assertTrue(old.exists())
        self.pending.unlink();self.run_policy(new);self.assertFalse(old.exists())
    def test_invalid_pending_cleans_nothing(self):
        old=self.backup('vps-security.AAAAAAAA');new=self.backup('vps-security.BBBBBBBB')
        self.pending.write_text('broken\n');self.run_policy(new,False);self.assertTrue(old.exists())
    def test_symlink_is_not_followed(self):
        outside=self.backup('unrelated');link=self.root/'vps-security.AAAAAAAA';link.symlink_to(outside,target_is_directory=True)
        new=self.backup('vps-security.BBBBBBBB');self.run_policy(new)
        self.assertTrue(link.is_symlink());self.assertTrue(outside.exists())

if __name__=='__main__':unittest.main()
