'use strict';
// Root finite metadata only; default/import performs no protected I/O.
const crypto=require('node:crypto');
const OLD_ID="a50ff5b4-6c39-41d5-8559-e76dd33cf663",PREVIOUS="./failed-operation-f895.cjs";
const ROWS=Object.freeze([
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/a50ff5b4-6c39-41d5-8559-e76dd33cf663/approval.json",
    "bytes": 1312,
    "sha256": "7ee69a988747de27a561db6a8de1cee2c8cba80f24096d6194f77b75ad0bd6fd"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/a50ff5b4-6c39-41d5-8559-e76dd33cf663/root-operation-once.json",
    "bytes": 257,
    "sha256": "a1b685ad82ac3ce40740a73d5c71d59588ceaa9f12861bda7c5c665cdd1c3e4d"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/a50ff5b4-6c39-41d5-8559-e76dd33cf663/export-once.json",
    "bytes": 118,
    "sha256": "75889731aa510e1b0930c6f644eb1e1694e984e5dc951a2e8ae40b8b4d5f130b"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/a50ff5b4-6c39-41d5-8559-e76dd33cf663/export-result.json",
    "bytes": 727,
    "sha256": "6eba18b796ecc730446c8161d086f95a9a3e12d56a29063b2db8543150a465f2"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/a50ff5b4-6c39-41d5-8559-e76dd33cf663/root-dispatch-proof.json",
    "bytes": 58797,
    "sha256": "9a5ad2e06add1ed780444aae1de2748a924ad3eed6bc13426c0552e5b8df838c"
  }
].map(Object.freeze));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const row of ROWS){const b=read(row.file,row.bytes);if(!Buffer.isBuffer(b)||b.length!==row.bytes||sha(b)!==row.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(row.file,b);}return held;}
function holdAll(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map([...require(PREVIOUS).holdAll(read),...hold(read)]);if(held.size!==25)throw Error('FAILED_HISTORY_REFUSED');return held;}
function same(held,read){if(!(held instanceof Map)||held.size!==25||typeof read!=='function')throw Error('FAILED_HISTORY_REFUSED');for(const[p,b]of held){const current=read(p,b.length);if(!Buffer.isBuffer(current)||!current.equals(b))throw Error('FAILED_HISTORY_REFUSED');}}
module.exports={OLD_ID,PREVIOUS,ROWS,hold,holdAll,same};
