"""Shared, dependency-free validation of untrusted compiled components. Never loads DLLs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zipfile

ENGINE_FILES = tuple('Binaries/Win64/UnrealEditor-'+m+'.dll' for m in
    ('Core','CoreUObject','Slate','SlateCore','ApplicationCore','InputCore','Engine','GraphEditor')) + tuple(
    'Plugins/FX/Niagara/Binaries/Win64/UnrealEditor-'+m+'.dll' for m in
    ('NiagaraEditor','NiagaraEditorWidgets','Niagara','NiagaraCore'))
MAX_BYTES = 20 * 1024 * 1024
MAX_EXPANDED = 48 * 1024 * 1024
MANIFESTS = ('bridge-manifest.json','module-index-manifest.json')


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def engine_identity(info):
    if not isinstance(info,dict) or not re.fullmatch(r'\d+\.\d+\.\d+',str(info.get('version',''))):
        raise ValueError('引擎版本格式无效。')
    hashes=info.get('sha256',{})
    if not isinstance(hashes,dict) or set(hashes)!=set(ENGINE_FILES):
        raise ValueError('需要完整的 12 项引擎指纹。')
    if any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in hashes.values()):
        raise ValueError('引擎指纹格式无效。')
    # Paths, computer names, branch names and user-supplied identity claims are not transmitted.
    return {'version':info['version'],'sha256':dict(hashes)}


def fingerprint(info):
    return sha(canonical(dict(engine=engine_identity(info),platform='Win64')))


def official_kind(info,catalog):
    identity=engine_identity(info)
    if catalog.get('schema')!=1 or not isinstance(catalog.get('engines'),list):
        raise ValueError('官方指纹目录无效，请稍后重试。')
    return 'official' if any(engine_identity(item['engine'])==identity for item in catalog['engines']) else 'custom'


def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d+(?:\.\d+){1,3}',value):
        raise ValueError('插件版本格式无效。')
    return value


def release_tag(info,plugin_version,kind):
    if kind not in ('official','custom'):raise ValueError('投稿分类无效。')
    return 'community-'+kind+'-'+version(plugin_version)+'-'+fingerprint(info)


def validate_dll(data):
    if len(data)<256 or data[:2]!=b'MZ':raise ValueError('编译组件不是 Windows DLL。')
    offset=struct.unpack_from('<I',data,60)[0]
    if offset+26>len(data) or data[offset:offset+4]!=b'PE\0\0':raise ValueError('DLL PE 头无效。')
    machine=struct.unpack_from('<H',data,offset+4)[0]
    flags=struct.unpack_from('<H',data,offset+22)[0]
    if machine!=0x8664 or not flags&0x2000:raise ValueError('只接收 Win64 DLL。')


def validate_bundle(path,catalog):
    """Inspect a fixed five-file ZIP without extracting or executing its contents."""
    path=Path(path)
    if path.stat().st_size>MAX_BYTES:raise ValueError('投稿包超过 20 MB。')
    with zipfile.ZipFile(path) as z:
        entries=z.infolist();names=[i.filename for i in entries]
        if len(entries)!=5 or len(set(n.casefold() for n in names))!=5:raise ValueError('投稿包文件数量或名称无效。')
        if sum(i.file_size for i in entries)>MAX_EXPANDED:raise ValueError('投稿包展开后过大。')
        for item in entries:
            p=PurePosixPath(item.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in item.filename or ':' in item.filename or item.is_dir():
                raise ValueError('投稿包包含非法路径。')
            if (item.external_attr>>16)&0o170000==0o120000:raise ValueError('投稿包不能包含链接。')
        if 'contribution.json' not in names or z.getinfo('contribution.json').file_size>16384:
            raise ValueError('投稿元数据缺失或过大。')
        meta=json.loads(z.read('contribution.json'))
        if set(meta)!={'schema','engine','platform','plugin_version','kind','custom_consent','fingerprint','files'}:
            raise ValueError('投稿元数据包含不支持的字段。')
        if meta['schema']!=1 or meta['platform']!='Win64':raise ValueError('投稿格式不支持。')
        if meta['engine']!=engine_identity(meta['engine']):raise ValueError('引擎元数据包含额外信息。')
        version(meta['plugin_version'])
        kind=official_kind(meta['engine'],catalog)
        if meta['kind']!=kind:raise ValueError('投稿分类与维护者官方指纹目录不符，请重新检查后生成投稿包。')
        if type(meta['custom_consent']) is not bool or (kind=='custom' and not meta['custom_consent']):
            raise ValueError('定制或未认证构建需要明确同意公开分享。')
        if meta['fingerprint']!=fingerprint(meta['engine']):raise ValueError('构建标识不匹配。')
        if not isinstance(meta['files'],dict) or set(meta['files'])!=set(names)-{'contribution.json'}:
            raise ValueError('投稿组件清单不匹配。')
        expected={'contribution.json'}
        for i,name in enumerate(MANIFESTS):
            relative='Binaries/Win64/'+name;expected.add(relative)
            if z.getinfo(relative).file_size>16384:raise ValueError('组件清单过大。')
            manifest=json.loads(z.read(relative))
            if set(manifest)!={'engine_sha256','bridge_file','bridge_sha256'}:raise ValueError('组件清单包含额外信息。')
            prefix='XHSlateBridge' if i==0 else 'XHModuleIndex'
            if not re.fullmatch(prefix+r'\d+\.dll',str(manifest['bridge_file'])):raise ValueError('动态组件名称无效。')
            if manifest['engine_sha256']!=meta['engine']['sha256']:raise ValueError('组件目标引擎不匹配。')
            dll='Binaries/Win64/'+manifest['bridge_file'];expected.add(dll)
            data=z.read(dll);validate_dll(data)
            if sha(data)!=manifest['bridge_sha256']:raise ValueError('动态组件哈希不匹配。')
        if set(names)!=expected:raise ValueError('投稿包包含额外文件。')
        if any(sha(z.read(n))!=v for n,v in meta['files'].items()):raise ValueError('投稿文件哈希不匹配。')
    return meta
