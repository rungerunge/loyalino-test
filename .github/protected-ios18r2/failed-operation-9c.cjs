'use strict';
// Root finite metadata only; default/import performs no protected I/O.
const crypto=require('node:crypto');
const OLD_ID="9c1a13ee-2f36-4f21-a065-7c4af835e0f7",PREVIOUS="./failed-operation-a50.cjs";
const ROWS=Object.freeze([
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/root-operation-once.json",
    "bytes": 257,
    "sha256": "e087e19516e951da4577b9ef451d934005b05e31407b61eec53c2d02cf8ed76d"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/github-dispatch-once.json",
    "bytes": 109,
    "sha256": "e619b169542f6744b14b4efa34f221029692148dd590e8d15e9bd9e918053f37"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/root-dispatch-proof.json",
    "bytes": 180733,
    "sha256": "b4dea9b2769f328669198c8c0489c359d58430c13bc2d1d506d8b35122ec3e99"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/key-cleanup.json",
    "bytes": 140,
    "sha256": "54d4e16509bfec684c95d4dd1b7ffb0f413898cecf0ec767468d51d3a99cd116"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/root-cleanup-52b6ef61-78b2-45c3-9c6d-412d597abf1c.json",
    "bytes": 1235,
    "sha256": "6af8e1b126633d0b6dae9278f0230b460082c33e2386dfdf4312459045c7803c"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/root-authenticated-failure-proof.json",
    "bytes": 2710,
    "sha256": "d98a1389bc541046415784ceeb7d3217c2f22530ca897403c0d48818b56fb7e1"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-runtime-config-20261006/protected/9c1a13ee-2f36-4f21-a065-7c4af835e0f7/root-status-c08776fe-3572-4298-9385-a3773e07e812.json",
    "bytes": 1932,
    "sha256": "9afe61ca2f21497e0ab693393941a7f76e3dda26c72bcb3a948f4ee82f496bdd"
  }
].map(Object.freeze));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const row of ROWS){const b=read(row.file,row.bytes);if(!Buffer.isBuffer(b)||b.length!==row.bytes||sha(b)!==row.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(row.file,b);}return held;}
function holdAll(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map([...require(PREVIOUS).holdAll(read),...hold(read)]);if(held.size!==32)throw Error('FAILED_HISTORY_REFUSED');return held;}
function same(held,read){if(!(held instanceof Map)||held.size!==32||typeof read!=='function')throw Error('FAILED_HISTORY_REFUSED');for(const[p,b]of held){const current=read(p,b.length);if(!Buffer.isBuffer(current)||!current.equals(b))throw Error('FAILED_HISTORY_REFUSED');}}
module.exports={OLD_ID,PREVIOUS,ROWS,hold,holdAll,same};
