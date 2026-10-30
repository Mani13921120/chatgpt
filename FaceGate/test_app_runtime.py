import os
import sqlite3
import unittest
from unittest.mock import patch
from app_catalog import App
import app_runtime as runtime


class AppRuntimeTests(unittest.TestCase):
    def test_same_filename_in_another_directory_is_not_protected(self):
        app=App.desktop(r'C:\Private\app.exe')
        self.assertTrue(runtime.matches(app,r'C:\Private\APP.exe'))
        self.assertFalse(runtime.matches(app,r'C:\Other\app.exe'))

    def test_package_identity_survives_executable_version_change(self):
        app=App('start:f!app','Store','Family!App',process_paths=(r'C:\Pkg\v1\App.exe',))
        self.assertTrue(runtime.matches(app,r'C:\Pkg\v2\App.exe',app_id='Family!App'))
        self.assertFalse(runtime.matches(app,r'C:\Pkg\v1\App.exe',app_id='Family!Other'))

    def test_shortcut_profiles_are_not_interchanged(self):
        app=App('profile','App',executable=r'C:\App\app.exe',process_paths=(r'C:\App\app.exe',),arguments=('--profile','one'))
        self.assertTrue(runtime.matches(app,r'C:\App\app.exe',[r'C:\App\app.exe','--profile','one']))
        self.assertFalse(runtime.matches(app,r'C:\App\app.exe',[r'C:\App\app.exe','--profile','two']))

    def test_shared_system_host_is_never_terminated_as_an_app(self):
        app=App.desktop(r'C:\Windows\explorer.exe')
        self.assertFalse(app.monitorable)
        self.assertFalse(runtime.matches(app,r'C:\Windows\explorer.exe'))

    def test_database_migrates_legacy_and_stores_packaged_app(self):
        with sqlite3.connect(':memory:') as con:
            con.execute('CREATE TABLE locked_apps(path TEXT PRIMARY KEY COLLATE NOCASE,display_name TEXT,enabled INTEGER)')
            con.execute('INSERT INTO locked_apps VALUES(?,?,1)',(r'C:\Legacy\app.exe','Legacy'))
            app=App('start:f!app','Store','Family!App')
            runtime.save_app(con,app)
            loaded=runtime.load_apps(con)
            self.assertEqual(len(loaded),2)
            self.assertEqual(loaded[app.key],app)

    def test_session_expires_after_process_exit_not_window_switch(self):
        now=[0.0];sessions=runtime.Sessions(lambda:now[0])
        sessions.grant('app');now[0]=20;sessions.observe({'app'})
        self.assertTrue(sessions.allows(['app']))
        now[0]=23;sessions.observe(set());self.assertTrue(sessions.allows(['app']))
        now[0]=26;sessions.observe(set());self.assertFalse(sessions.allows(['app']))

    def test_updating_case_insensitive_legacy_record_keeps_it_monitorable(self):
        with sqlite3.connect(':memory:') as con:
            con.execute('CREATE TABLE locked_apps(path TEXT PRIMARY KEY COLLATE NOCASE,display_name TEXT,enabled INTEGER)')
            old=r'C:\Legacy\APP.EXE'
            con.execute('INSERT INTO locked_apps VALUES(?,?,1)',(old,'Legacy'))
            runtime.save_app(con,App.desktop(r'c:\legacy\app.exe'))
            loaded=runtime.load_apps(con)
            self.assertIn(old,loaded)
            self.assertEqual(loaded[old].key,old)

    def test_launch_override_cannot_redirect_to_another_executable(self):
        app=App.desktop(r'C:\App\safe.exe')
        with self.assertRaises(ValueError):runtime.launch(app,[r'C:\Other\bad.exe'])

    @unittest.skipUnless(os.name=='nt','Requires Windows application identity API')
    def test_query_unpacked_python_process_identity(self):
        self.assertEqual(runtime.process_app_id(os.getpid()),'')


if __name__=='__main__':unittest.main()
