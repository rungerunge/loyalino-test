'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function fail(){throw Error('PROTECTED_SOURCE_REFUSED');}
function read(file,max=1048576){if(typeof file!=='string'||!path.isAbsolute(file)||!Number.isSafeInteger(max)||max<1)fail();const s=fs.lstatSync(file),real=fs.realpathSync.native(file);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size<1||s.size>max||path.normalize(real).toLowerCase()!==path.normalize(file).toLowerCase())fail();const fd=fs.openSync(file,fs.constants.O_RDONLY);try{const t=fs.fstatSync(fd);if(!same(s,t))fail();const b=Buffer.alloc(s.size);let n=0;while(n<b.length){const count=fs.readSync(fd,b,n,b.length-n,n);if(count<1)fail();n+=count;}const extra=Buffer.alloc(1);if(fs.readSync(fd,extra,0,1,n)!==0||!same(s,fs.fstatSync(fd))||!same(s,fs.lstatSync(file))||fs.realpathSync.native(file)!==real)fail();return b;}finally{fs.closeSync(fd);}}
function same(a,b){return ['dev','ino','nlink','mode','size','mtimeMs','ctimeMs'].every(k=>a[k]===b[k]);}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');

const FROZEN_PYTHON="C:/Users/runge/.nevermonday-secrets/python-exact-pin-recovery-20261012/python31214-d41-stdlib-private/python.exe",FROZEN_MANIFEST="C:/Users/runge/.nevermonday-secrets/python-exact-pin-recovery-20261012/stdlib-runtime-manifest.json",FROZEN_MANIFEST_SHA="bf665ed8dfa02cffcacc248d0048248a229a7b4e7426987a2b1ddb8eb2f946bb",FROZEN_PY_SHA="d41bad46673f64e0d02f23797f53f90ccf60f27d6eda8d86dd2d4bbeae5a858c";
function frozenRuntime(rows){
 const wanted=rows.filter(r=>path.normalize(r.file).toLowerCase()===path.normalize(FROZEN_PYTHON).toLowerCase());if(!wanted.length)return;
 if(wanted.length!==1||wanted[0].bytes!==107312||wanted[0].sha256!==FROZEN_PY_SHA)fail();
 const raw=read(FROZEN_MANIFEST,2000000);if(sha(raw)!==FROZEN_MANIFEST_SHA)fail();const m=JSON.parse(raw);
 if(m.kind!=='IMMUTABLE_PYTHON31214_STDLIB_ONLY_SNAPSHOT'||m.exeBytes!==107312||m.exeSha256!==FROZEN_PY_SHA||m.rows?.length!==780||m.sitePackagesExcluded!==true||m.managedRuntimeModified!==false)fail();
 const base=path.resolve(path.dirname(FROZEN_PYTHON)),prefix=base+path.sep,expected=new Map();
 for(const r of m.rows){if(!path.isAbsolute(r.file)||!path.resolve(r.file).startsWith(prefix)||!Number.isSafeInteger(r.bytes)||r.bytes<0||!(/^[a-f0-9]{64}$/).test(r.sha256))fail();const key=path.resolve(r.file).toLowerCase();if(expected.has(key))fail();expected.set(key,r);}
 const seen=new Set();
 function walk(dir){const ds=fs.lstatSync(dir);if(!ds.isDirectory()||ds.isSymbolicLink()||path.normalize(fs.realpathSync.native(dir)).toLowerCase()!==path.normalize(dir).toLowerCase())fail();for(const name of fs.readdirSync(dir)){const file=path.join(dir,name),st=fs.lstatSync(file);if(st.isSymbolicLink())fail();if(st.isDirectory())walk(file);else if(st.isFile()){const key=path.resolve(file).toLowerCase(),r=expected.get(key);if(!r||seen.has(key)||st.nlink!==1||st.size!==r.bytes||path.normalize(fs.realpathSync.native(file)).toLowerCase()!==key)fail();const b=fs.readFileSync(file);if(b.length!==r.bytes||sha(b)!==r.sha256||!same(st,fs.lstatSync(file)))fail();seen.add(key);}else fail();}}
 walk(base);if(seen.size!==780||seen.size!==expected.size||sha(read(FROZEN_MANIFEST,2000000))!==FROZEN_MANIFEST_SHA)fail();
}

function hold(rows,root){if(!Array.isArray(rows)||rows.length<1||rows.length>1000)fail();const out=[];for(const r of rows){if(!r||Object.keys(r).sort().join(',')!=='bytes,file,sha256'||!Number.isSafeInteger(r.bytes)||r.bytes<1||!(/^[a-f0-9]{64}$/).test(r.sha256))fail();const file=path.isAbsolute(r.file)?r.file:path.join(root,r.file);if(!path.isAbsolute(r.file)&&!(/^[A-Za-z0-9_.-]+$/).test(r.file))fail();const b=read(file,r.bytes);if(b.length!==r.bytes||sha(b)!==r.sha256)fail();out.push({file,bytes:r.bytes,sha256:r.sha256});}frozenRuntime(out);return out;}
function check(rows){hold(rows,'');}
function startup(env,args){if(args.length||['NODE_OPTIONS','NODE_DEBUG','NODE_DEBUG_NATIVE','DEBUG','RUST_LOG'].some(k=>env[k]!==undefined&&env[k]!==''))fail();for(const [k,v]of Object.entries(env))if(v&&(/proxy/i.test(k)||/^(EXPO_API_URL|EXPO_STAGING|EAS_LOCAL_BUILD|EAS_BUILD|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|SSL_CERT_DIR)/.test(k)))fail();}
module.exports={read,same,sha,hold,check,startup,frozenRuntime};
