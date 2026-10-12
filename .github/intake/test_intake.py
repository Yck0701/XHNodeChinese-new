import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import contribution_protocol as p
import intake


class IntakeTests(unittest.TestCase):
    def test_only_github_attachment(self):
        marker='<!-- XH-CONTRIBUTION-SHA256:'+'a'*64+' -->'
        url='https://github.com/user-attachments/files/123/XH-contribution.zip'
        self.assertEqual(intake.attachment(marker+'\n[file]('+url+')'),(url,'a'*64))
        for bad in ('https://example.com/file.zip','http://169.254.169.254/a.zip',url+'/extra'):
            with self.assertRaises(ValueError):intake.attachment(marker+'\n'+bad)

    def test_multiple_attachments_rejected(self):
        with self.assertRaises(ValueError):intake.attachment('<!-- XH-CONTRIBUTION-SHA256:'+'a'*64+' -->\nhttps://github.com/user-attachments/files/1/a.zip\nhttps://github.com/user-attachments/files/2/b.zip')

    def test_custom_body_consent_required(self):
        meta={'kind':'custom'}
        with patch.object(p,'validate_bundle',return_value=meta),patch.object(intake,'api') as api:
            with self.assertRaises(ValueError):intake.collect('x',{},'',{})
        api.assert_not_called()

    def test_protocol_roundtrip_and_untrusted_claim(self):
        engine={'version':'5.8.3','sha256':{n:'a'*64 for n in p.ENGINE_FILES}}
        catalog={'schema':1,'engines':[{'engine':engine}]}
        data=bytearray(300);data[:2]=b'MZ';struct.pack_into('<I',data,60,128)
        data[128:132]=b'PE\0\0';struct.pack_into('<H',data,132,0x8664);struct.pack_into('<H',data,150,0x2000)
        files={}
        for i,name in enumerate(p.MANIFESTS):
            binary=('XHSlateBridge0214.dll','XHModuleIndex0214.dll')[i]
            files['Binaries/Win64/'+binary]=bytes(data)
            files['Binaries/Win64/'+name]=p.canonical(dict(engine_sha256=engine['sha256'],bridge_file=binary,bridge_sha256=p.sha(data)))
        meta=dict(schema=1,engine=engine,platform='Win64',plugin_version='0.2.14',kind='official',custom_consent=False,fingerprint=p.fingerprint(engine),files={n:p.sha(d) for n,d in files.items()})
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bundle.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('contribution.json',p.canonical(meta))
                for n,d in files.items():z.writestr(n,d)
            self.assertEqual(p.validate_bundle(path,catalog),meta)
            with self.assertRaises(ValueError):p.validate_bundle(path,{'schema':1,'engines':[]})

    def test_download_rejects_internal_host_before_open(self):
        with patch.object(intake,'build_opener') as opener:
            with self.assertRaises(ValueError):intake.download_attachment('https://127.0.0.1/x','not-created')
            opener.return_value.open.assert_not_called()

    def test_new_storage_stays_pending_and_never_latest(self):
        engine={'version':'5.8.3','sha256':{n:'a'*64 for n in p.ENGINE_FILES}}
        for kind in ('official','custom'):
            meta={'kind':kind,'engine':engine,'plugin_version':'0.2.14'}
            issue={'html_url':'https://github.com/'+intake.REPO+'/issues/1','number':1}
            release={'id':2,'html_url':'https://github.com/'+intake.REPO+'/releases/tag/x','upload_url':'https://uploads.github.com/repos/'+intake.REPO+'/releases/2/assets{?name}'}
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'bundle.zip';path.write_bytes(b'validated fixture')
                with patch.object(p,'validate_bundle',return_value=meta),patch.object(intake,'maybe',return_value=None),patch.object(intake,'api',return_value=release) as api,patch.object(intake,'upload') as upload,patch.object(intake,'index_entry') as index:
                    url,duplicate=intake.collect(path,{},intake.CONSENT,issue)
                self.assertFalse(duplicate);self.assertEqual(upload.call_count,2)
                create=api.call_args_list[0].args[2];finish=api.call_args_list[-1].args[2]
                self.assertTrue(create['draft']);self.assertTrue(finish['prerelease']);self.assertEqual(finish['make_latest'],'false')
                self.assertTrue(create['tag_name'].startswith('community-'+kind+'-'))
                record=index.call_args.args[1]
                self.assertEqual(record['state'],'pending_review');self.assertFalse(record['verified'])

    def test_existing_asset_is_never_overwritten(self):
        release={'id':2,'upload_url':'https://uploads.github.com/repos/'+intake.REPO+'/releases/2/assets{?name}'}
        with patch.object(intake,'api',return_value=[{'name':'components.zip','digest':'sha256:'+'a'*64}]),patch.object(intake,'urlopen') as network:
            with self.assertRaises(ValueError):intake.upload(release,'components.zip',b'different')
        network.assert_not_called()


if __name__=='__main__':unittest.main()
