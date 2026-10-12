"""GitHub intake: only inspect five-file native bundles; never execute contributed code."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile
from urllib.error import HTTPError
from urllib.parse import urlparse,urlencode
from urllib.request import Request,urlopen,HTTPRedirectHandler,build_opener

import contribution_protocol as protocol

REPO='Yck0701/XHNodeChinese-new'
CONSENT='- [x] 我同意公开分享此定制或未认证构建的插件组件及引擎指纹。'


def api(path,method='GET',data=None):
    headers={'Accept':'application/vnd.github+json','User-Agent':'XH-Build-Intake',
             'Authorization':'Bearer '+os.environ['GH_TOKEN']}
    if data is not None:headers['Content-Type']='application/json'
    req=Request('https://api.github.com/'+path,headers=headers,method=method,
                data=None if data is None else json.dumps(data).encode())
    with urlopen(req,timeout=45) as r:return json.load(r)


def maybe(path):
    try:return api(path)
    except HTTPError as error:
        if error.code==404:return None
        raise


def attachment(body):
    hashes=re.findall(r'<!-- XH-CONTRIBUTION-SHA256:([0-9a-f]{64}) -->',body)
    urls=re.findall(r'https://github\.com/user-attachments/files/[0-9]+/[A-Za-z0-9_.-]+\.zip(?=[\s)\]>]|$)',body)
    if len(hashes)!=1 or len(set(urls))!=1:raise ValueError('请保留管理器生成的校验标记，并上传一个投稿 ZIP 附件。')
    return urls[0],hashes[0]


def download_attachment(url,dest):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=build_opener(NoRedirect())
    for _ in range(6):
        parsed=urlparse(url)
        host=parsed.hostname or ''
        if parsed.scheme!='https' or parsed.username or parsed.password or parsed.port not in (None,443):raise ValueError('附件地址无效。')
        if host not in ('github.com','objects.githubusercontent.com','release-assets.githubusercontent.com') and not re.fullmatch(r'github-production-user-asset-[a-z0-9-]+\.s3\.amazonaws\.com',host):
            raise ValueError('附件跳转到了不允许的主机。')
        try:
            response=opener.open(Request(url,headers={'User-Agent':'XH-Build-Intake'}),timeout=45)
        except HTTPError as error:
            if error.code in (301,302,303,307,308):url=error.headers['Location'];continue
            raise
        total=0
        with response,Path(dest).open('xb') as f:
            while True:
                chunk=response.read(65536)
                if not chunk:break
                total+=len(chunk)
                if total>protocol.MAX_BYTES:raise ValueError('投稿包超过 20 MB。')
                f.write(chunk)
        return
    raise ValueError('附件跳转次数过多。')


def upload(release,name,data):
    base=release['upload_url'].split('{')[0]
    parsed=urlparse(base)
    if parsed.scheme!='https' or parsed.hostname!='uploads.github.com' or not parsed.path.startswith('/repos/'+REPO+'/releases/'):
        raise ValueError('上传地址不可信。')
    existing=api('repos/'+REPO+'/releases/'+str(release['id'])+'/assets')
    present=next((a for a in existing if a['name']==name),None)
    expected='sha256:'+protocol.sha(data)
    if present:
        if present.get('digest')!=expected:raise ValueError('已有投稿附件不同，保留原附件供维护者处理。')
        return
    req=Request(base+'?'+urlencode({'name':name}),data=data,method='POST',headers={
        'Authorization':'Bearer '+os.environ['GH_TOKEN'],'User-Agent':'XH-Build-Intake','Content-Type':'application/octet-stream'})
    with urlopen(req,timeout=90) as response:asset=json.load(response)
    if asset.get('digest')!=expected:raise ValueError('云端附件校验失败。')


def index_entry(tag,record):
    import base64
    path='repos/'+REPO+'/contents/catalog/community-builds.json'
    current=api(path)
    data=json.loads(base64.b64decode(current['content']))
    data['builds'][tag]=record
    api(path,'PUT',{'message':'Index contributed build '+tag,'sha':current['sha'],
                   'content':base64.b64encode(protocol.canonical(data)+b'\n').decode()})


def collect(path,catalog,body,issue):
    meta=protocol.validate_bundle(path,catalog)
    if meta['kind']=='custom' and CONSENT not in body:raise ValueError('投稿正文缺少定制构建公开分享的同意记录。')
    tag=protocol.release_tag(meta['engine'],meta['plugin_version'],meta['kind'])
    route='repos/'+REPO+'/releases'
    release=maybe(route+'/tags/'+tag)
    if release and not release['draft']:
        assets=api(route+'/'+str(release['id'])+'/assets')
        saved=next((a for a in assets if a['name']=='submission.json'),None)
        if not saved:raise ValueError('已有存档缺少收录记录，需维护者处理。')
        with urlopen(Request(saved['browser_download_url'],headers={'User-Agent':'XH-Build-Intake'}),timeout=30) as r:
            raw=r.read(16385)
        if len(raw)>16384 or saved.get('digest')!='sha256:'+protocol.sha(raw):raise ValueError('存档记录校验失败。')
        record=json.loads(raw)
        if protocol.release_tag(record['engine'],record['plugin_version'],record['kind'])!=tag:
            raise ValueError('存档记录不匹配。')
        index_entry(tag,record)
        return release['html_url'],True
    if not release:
        release=api(route,'POST',{'tag_name':tag,'name':('官方指纹投稿' if meta['kind']=='official' else '定制／未认证投稿')+
                    ' · UE '+meta['engine']['version']+' · 插件 '+meta['plugin_version'],
                    'body':'等待维护者在对应引擎验证。此处仅保存投稿组件，不是可安装的正式插件包。\n\n来源：'+issue['html_url'],
                    'draft':True,'prerelease':True,'make_latest':'false'})
    # A successful writer never replaces another user's contributed binary.
    archive=Path(path).read_bytes()
    upload(release,'components.zip',archive)
    record={'state':'pending_review','kind':meta['kind'],'engine':meta['engine'],
            'plugin_version':meta['plugin_version'],'platform':'Win64','sha256':protocol.sha(archive),
            'issue':issue['number'],'release_url':'https://github.com/'+REPO+'/releases/tag/'+tag,'verified':False}
    upload(release,'submission.json',protocol.canonical(record))
    release=api(route+'/'+str(release['id']),'PATCH',{'draft':False,'prerelease':True,'make_latest':'false'})
    index_entry(tag,record)
    return release['html_url'],False


def comment(issue,text):
    prefix='<!-- xh-build-intake -->\n'
    route='repos/'+REPO+'/issues/'+str(issue['number'])+'/comments'
    previous=api(route+'?per_page=100')
    own=next((c for c in previous if c['user']['login']=='github-actions[bot]' and c['body'].startswith(prefix)),None)
    if own:api('repos/'+REPO+'/issues/comments/'+str(own['id']),'PATCH',{'body':prefix+text})
    else:api(route,'POST',{'body':prefix+text})


def main():
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    issue=event.get('issue',{})
    if issue.get('pull_request') or not issue.get('title','').startswith('[构建投稿]'):return
    if event['repository']['full_name']!=REPO:raise ValueError('不允许写入其他仓库。')
    body=issue.get('body') or ''
    # Opening an incomplete draft in the browser does not run this; submitting without an attachment gives a repair message.
    try:
        url,expected=attachment(body)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'components.zip';download_attachment(url,path)
            if protocol.sha(path.read_bytes())!=expected:raise ValueError('附件与管理器生成的 SHA-256 不匹配。')
            catalog=json.loads(Path('catalog/official-engines.json').read_text())
            url,duplicate=collect(path,catalog,body,issue)
        comment(issue,('该构建已收录，无需重复上传。' if duplicate else '已校验并独立收录，等待维护者验证。')+
                '\n\n[查看投稿存档]('+url+')\n\n通过对应引擎的功能验证后才会加入正式更新清单。')
    except (ValueError,KeyError,TypeError,UnicodeError,zipfile.BadZipFile) as error:
        # Do not quote attacker-supplied text or file names in a privileged bot response.
        comment(issue,'投稿校验未通过。请使用最新版管理器重新生成投稿包，并保留校验标记与定制分享同意记录；编辑此投稿后会重新检查。')
        raise ValueError('Submission validation failed') from error


if __name__=='__main__':main()
