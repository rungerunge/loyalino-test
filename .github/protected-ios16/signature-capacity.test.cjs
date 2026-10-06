'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const P=require('./policy.cjs'),F=require('./fixtures.cjs'),D=require('./signature-source.cjs'),History=require('./failed-operation-9c.cjs');
const PARENT='C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006';
const REVIEW_SHA='0eecbefcfd0842e9d178e4536c7210ec5ef243bc209b5f320c0f41b3b8d09539';
const readOwn=name=>fs.readFileSync(path.join(__dirname,name),'utf8');
function fictional(){
  const names=['failed-operation.cjs','failed-operation-c0a.cjs','failed-operation-f895.cjs','failed-operation-a50.cjs','failed-operation-9c.cjs'];
  const rows=names.flatMap(n=>require('./'+n).ROWS),buffers=new Map(rows.map((r,i)=>[r.file,Buffer.alloc(r.bytes,i+1)])),modules=new Map();
  const fakeCrypto={createHash(){return{update(b){this.b=Buffer.from(b);return this;},digest(){return rows.find(r=>buffers.get(r.file).equals(this.b))?.sha256||crypto.createHash('sha256').update(this.b).digest('hex');}};}};
  function load(name){name=path.basename(name);if(modules.has(name))return modules.get(name);const m={exports:{}};new Function('require','module','exports',readOwn(name))(n=>n==='node:crypto'?fakeCrypto:load(n),m,m.exports);modules.set(name,m.exports);return m.exports;}
  return{H:load('./failed-operation-9c.cjs'),rows,buffers,read:(name,bytes)=>{const b=buffers.get(name);if(!b||b.length!==bytes)throw Error('FICTIONAL_HISTORY_REFUSED');return Buffer.from(b);}};
}
test('exact352 public parent rows and receipt are held without protected history bodies',()=>{
  const bytes=fs.readFileSync(PARENT+'/source-review.json'),parent=JSON.parse(bytes);
  assert.equal(P.sha(bytes),REVIEW_SHA);
  const expected=[...parent.sourceDependencies,...parent.files.map(r=>({...r,file:PARENT+'/'+r.file})),{file:PARENT+'/source-review.json',bytes:bytes.length,sha256:REVIEW_SHA}];
  const current=JSON.parse(readOwn('source-dependencies.json'));
  assert.equal(expected.length,352);assert.deepEqual(current,expected);
  assert.equal(new Set(current.map(r=>r.file)).size,352);
  assert.ok(current.every(r=>!r.file.includes('/protected/')));
});
test('complete native source derives exactly and restores every original accepting byte',()=>{
  const old=fs.readFileSync(PARENT+'/native-audit.py','utf8'),current=readOwn('native-audit.py');
  assert.equal(current,D.native(old));assert.equal(D.restoreNative(current),old);
  assert.throws(()=>D.native(old+'\n'));assert.throws(()=>D.restoreNative(current.replace('not any(code[length:])','True')));
  assert.ok(current.includes('    length = len(code)\n    blobs, spans = {}, []'));
});
test('policy derives only the two new spent UUID denials',()=>{
  const old=fs.readFileSync(PARENT+'/policy.cjs','utf8');assert.equal(readOwn('policy.cjs'),D.policy(old));
  for(const id of [D.OLD_A50,D.OLD_9C,'004dcd70-4e30-4ef6-97a0-47b984e6b131','c0a2142a-c51b-41a1-9e9e-8ecbdacba1fd','f8955263-133c-4d9f-92fe-b915f7722c23']){
    const a=F.approval();a.operationId=id;a.environmentName='nm-ios16-'+id;assert.throws(()=>P.approval(a,F.NOW));
  }
  assert.equal(P.approval(F.approval(),F.NOW).version,16);
});
test('original fixed600s approval and120s repository freshness boundaries stay strict',()=>{
  const a=F.approval();assert.equal(P.approval(a,F.NOW+599999),a);assert.throws(()=>P.approval(a,F.NOW+600000));
  const longer=structuredClone(a);longer.expiresAt=new Date(F.NOW+600001).toISOString();assert.throws(()=>P.approval(longer,F.NOW));
  const r={repository:P.REPOSITORY,public:true,archived:false,disabled:false,admin:true,actionsEnabled:true,unexpectedWriters:0,workflowsReviewed:true,refSha:'a'.repeat(40),observedAt:new Date(F.NOW-120000).toISOString()};
  assert.equal(P.repository(r,F.NOW),r);r.observedAt=new Date(F.NOW-120001).toISOString();assert.throws(()=>P.repository(r,F.NOW));
});
test('Root export and receive have exactly the old bodies with checked32-history routing',()=>{
  for(const name of ['root-export.cjs','root-receive.cjs'])assert.equal(readOwn(name),D.rootHistory(fs.readFileSync(PARENT+'/'+name,'utf8')));
  assert.throws(()=>D.rootHistory('missing anchors'));
});
test('history imports perform no protected I/O and preserve20 plus5 plus7 finite rows',()=>{
  assert.equal(History.ROWS.length,7);assert.equal(require('./failed-operation-a50.cjs').ROWS.length,5);
  assert.equal(History.ROWS[2].bytes,180733);assert.equal(History.ROWS[5].sha256,'d98a1389bc541046415784ceeb7d3217c2f22530ca897403c0d48818b56fb7e1');
  assert.throws(()=>History.hold());assert.throws(()=>History.holdAll());
  const f=fictional();assert.equal(f.rows.length,32);assert.equal(new Set(f.rows.map(r=>r.file)).size,32);
});
test('all32 genuine-shaped fictional historical descriptors must be held and stable',()=>{
  const f=fictional(),held=f.H.holdAll(f.read);assert.equal(held.size,32);f.H.same(held,f.read);
  assert.deepEqual([...held.keys()],f.rows.map(r=>r.file));
});
test('every one of32 held histories refuses byte drift without replay',()=>{
  for(let i=0;i<32;i++){const f=fictional(),held=f.H.holdAll(f.read);f.buffers.get(f.rows[i].file)[0]^=1;assert.throws(()=>f.H.same(held,f.read));}
});
test('missing or malformed current history cannot become a valid hold',()=>{
  assert.throws(()=>History.same(new Map(),()=>Buffer.alloc(0)));
  assert.throws(()=>History.hold(()=>Buffer.alloc(0)));assert.throws(()=>History.hold(()=> 'PRIVATE'));
  const f=fictional(),held=f.H.holdAll(f.read);assert.throws(()=>f.H.same(held,()=> 'PRIVATE'));
});
test('actual Root lexical boundary checks all32 after both original source checks',()=>{
  for(const name of ['root-export.cjs','root-receive.cjs']){
    const match=/check=\(\)=>\{held\.check\(\);H\.check\(deps\);require\('\.\/failed-operation-9c\.cjs'\)\.same\(history,H\.read\);\}/.exec(readOwn(name));assert.ok(match);
    const f=fictional(),history=f.H.holdAll(f.read),events=[];let drift=false;
    const check=new Function('held','H','deps','history','require','const '+match[0]+';return check;')({check:()=>events.push('source')},{check:()=>{events.push('deps');if(drift)f.buffers.get(f.rows[31].file)[0]^=1;},read:f.read},[],history,()=>f.H);
    check();assert.deepEqual(events,['source','deps']);drift=true;assert.throws(check);
  }
});
test('whole actual Root receiver executes guarded read-only transport with all32 history ports',async()=>{
  const f=fictional(),root='C:/fictional/capacity',id=F.ID,runId=123,approval=F.approval(),boot=Buffer.from('fictional-bootstrap'),review=Buffer.from(JSON.stringify({files:[{file:'bootstrap.cjs',sha256:P.sha(boot)}],sourceDependencies:[]}));
  approval.sourceReviewSha256=P.sha(review);const output=Buffer.from('fictional-cipher'),request={releaseId:44,outputAssetId:55,outputCipherSha256:P.sha(output),outputCipherBytes:output.length},dir=path.join(root,'protected',id);
  const map=new Map([[path.join(dir,'approval.json'),Buffer.from(JSON.stringify(approval))],[path.join(root,'source-review.json'),review],[path.join(root,'bootstrap.cjs'),boot],[path.join(dir,'return-request.json'),Buffer.from(JSON.stringify(request))],[path.join(dir,'input-'+id+'.nmae'),Buffer.from('fictional-input')],[path.join(dir,'key.bin'),Buffer.alloc(32,1)]]),events=[],read=(p,n)=>map.has(p)?Buffer.from(map.get(p)):f.read(p,n),fakeProcess={env:{PATH:'C:/fictional'},execArgv:[]};
  function api(args){const endpoint=args[3];if(endpoint.endsWith('/jobs?filter=all'))return{total_count:1,jobs:[{run_id:runId,run_attempt:1,status:'completed',conclusion:'success',labels:['macos-26'],started_at:'2026-10-06T00:00:00Z',completed_at:'2026-10-06T00:01:00Z'}]};if(endpoint.includes('/actions/runs/'))return{repository:{full_name:P.REPOSITORY},actor:{login:P.ACTOR},event:'workflow_dispatch',run_attempt:1,head_sha:approval.workflowCommit,path:'.github/workflows/nm-protected-ios16.yml',status:'completed',conclusion:'success'};if(endpoint.includes('/releases/'))return{assets:[{id:55,name:'output-'+id+'.nmae',state:'uploaded',size:output.length,digest:'sha256:'+P.sha(output)}]};throw Error('UNEXPECTED_FICTIONAL_GET');}
  const gm={exports:{}};new Function('require','module','exports','process',readOwn('root-github.cjs'))(n=>n==='node:child_process'?{spawnSync(file,args){events.push('GET');return{status:0,error:false,signal:null,stdout:Buffer.from(JSON.stringify(api(args))),stderr:Buffer.alloc(0)};}}:n==='./policy.cjs'?P:n==='./held-source.cjs'?{read}:n==='./root-export.cjs'?{rootEnvironment:()=>({})}:require(n),gm,gm.exports,fakeProcess);
  const rm={exports:{}};new Function('require','module','exports','__dirname','process',readOwn('root-receive.cjs'))(n=>n==='node:fs'?{readFileSync:p=>{assert.ok(map.has(p));return Buffer.from(map.get(p));}}:n==='./bootstrap.cjs'?{hold:()=>({v:{sourceDependencies:[]},check:()=>events.push('source')})}:n==='./held-source.cjs'?{startup(){},hold:()=>[],check:()=>events.push('deps'),read}:n==='./failed-operation-9c.cjs'?f.H:n==='./root-github.cjs'?gm.exports:n==='./policy.cjs'?P:n==='./github-release.cjs'?{MAX_CIPHER:1000000,release:v=>v,request:async()=>{events.push('binary');return output;}}:n==='./root-export.cjs'?{rootEnvironment:()=>({})}:n==='./receiver.cjs'?{receive:async(a,i,o,k,actual,ports)=>{ports.check();assert.equal(actual.runId,runId);assert.equal(k.length,32);assert.ok(o.equals(output));events.push('receive');return{transportRouteChecked:true,nativeAcceptance:false};}}:require(n),rm,rm.exports,root,fakeProcess);
  assert.deepEqual(await rm.exports.execute(id,runId),{transportRouteChecked:true,nativeAcceptance:false});
  assert.equal(events.filter(v=>v==='GET').length,3);assert.equal(events.filter(v=>v==='binary').length,1);
  for(const i of events.map((v,i)=>v==='GET'||v==='binary'?i:-1).filter(i=>i>=0)){assert.deepEqual(events.slice(i-2,i),['source','deps']);assert.deepEqual(events.slice(i+1,i+3),['source','deps']);}
});
test('old histories and all undeclared accepting dependencies retain original bytes',()=>{
  const review=JSON.parse(fs.readFileSync(PARENT+'/source-review.json'));
  const changed=new Set(['native-audit.py','policy.cjs','root-export.cjs','root-receive.cjs','source-dependencies.json','prepare-review.cjs','README.md']);
  for(const row of review.files)if(!changed.has(row.file))assert.ok(fs.readFileSync(PARENT+'/'+row.file).equals(fs.readFileSync(__dirname+'/'+row.file)),row.file);
});
test('default source derivation is pure and all historical destinations stay outside new operation namespace',()=>{
  assert.ok(History.ROWS.every(r=>r.file.startsWith(PARENT+'/protected/'+D.OLD_9C+'/')));
  assert.ok(require('./failed-operation-a50.cjs').ROWS.every(r=>r.file.startsWith(PARENT+'/protected/'+D.OLD_A50+'/')));
  assert.ok(!readOwn('signature-source.cjs').includes("require('node:fs')"));
  assert.ok(readOwn('policy.cjs').includes('VERSION=16'));
  assert.ok(readOwn('runner.cjs').includes('__API_SERVER_URL'));
});
