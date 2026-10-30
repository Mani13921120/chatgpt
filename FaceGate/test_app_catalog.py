import base64
import json
import os
import subprocess
import unittest
from app_catalog import parse_catalog, search_key, split_arguments, discover, App


class CatalogTests(unittest.TestCase):
    def test_keeps_same_name_and_same_executable_distinct_apps(self):
        rows=[{'id':'Vendor.One!App','name':'Example','executable':r'C:\App\host.exe','arguments':'--profile one'},
              {'id':'Vendor.Two!App','name':'Example','executable':r'C:\App\host.exe','arguments':'--profile two'}]
        apps,warnings=parse_catalog({'apps':rows})
        self.assertEqual(len(apps),2)
        self.assertNotEqual(apps[0].key,apps[1].key)

    def test_merges_same_identity_without_losing_shortcut_arguments(self):
        apps,_=parse_catalog({'apps':[{'id':'Desktop.App','name':'App','sources':['Start']},
            {'id':'desktop.app','name':'App','executable':r'C:\App\app.exe','arguments':'--profile "Work User"','sources':['Shortcut']}]})
        self.assertEqual(len(apps),1)
        self.assertEqual(apps[0].arguments,('--profile','Work User'))
        self.assertEqual(set(apps[0].sources),{'Start','Shortcut'})

    def test_shared_package_executable_does_not_become_path_match(self):
        apps,_=parse_catalog({'apps':[{'id':'Family!App','name':'Store App','executable':r'C:\Package\shared.exe','path_unique':False}]})
        self.assertEqual(apps[0].process_paths,())
        self.assertTrue(apps[0].monitorable)

    def test_windows_arguments_and_persian_search(self):
        self.assertEqual(split_arguments('--name "Work User" "" --flag'),('--name','Work User','','--flag'))
        self.assertEqual(search_key('كي\u200cبورد'),search_key('کیبورد'))

    def test_unknown_app_remains_visible_instead_of_fake_executable(self):
        apps,_=parse_catalog({'apps':[{'id':'unknown.desktop','name':'Installed app'}]})
        self.assertEqual(len(apps),1)
        self.assertFalse(apps[0].monitorable)

    def test_serialization_keeps_launch_identity(self):
        app=App('start:family!app','Store App','Family!App',process_paths=(r'C:\Pkg\App.exe',))
        self.assertEqual(App.from_json(app.to_json()),app)


@unittest.skipUnless(os.name=='nt','Requires actual Windows Start catalog')
class WindowsCatalogTests(unittest.TestCase):
    def test_all_current_start_ids_are_present(self):
        apps,warnings=discover()
        self.assertTrue(apps,'Windows returned an empty catalog')
        self.assertNotIn('Get-StartApps unavailable',warnings)
        script="[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); @(Get-StartApps | ForEach-Object {$_.AppID}) | ConvertTo-Json -Compress"
        encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=60)
        self.assertEqual(result.returncode,0)
        expected=json.loads(result.stdout.decode('utf-8-sig'))
        if isinstance(expected,str):expected=[expected]
        actual={a.app_id.casefold() for a in apps}
        missing={s.casefold() for s in expected if s}-actual
        self.assertFalse(missing,'Missing Start identities: '+repr(sorted(missing)))


if __name__=='__main__':unittest.main()
