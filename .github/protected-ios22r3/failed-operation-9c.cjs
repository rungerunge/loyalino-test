'use strict';
// Root finite metadata only; default/import performs no protected I/O.
const crypto=require('node:crypto');
const OLD_ID="9c1a13ee-2f36-4f21-a065-7c4af835e0f7",PREVIOUS="./failed-operation-a50.cjs";
const ROWS=Object.freeze([{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/source-review.json","bytes":256226,"sha256":"058a9b20447915ae4a4e69e597be46703371389fe44cf79bab6026b6222469b8"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/launcher-review.json","bytes":1579,"sha256":"8f97e742a75bad1b9614f9fcad00d8104df85f7ead2a830b3fef27d61f26e8b8"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/operational-review.json","bytes":2922,"sha256":"e153553bde4fa2e919bd38cc1df2b2a00df2f391254ed2677971f0e3c0fcac7e"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/operator-process-result.json","bytes":216,"sha256":"4582fef3f34a9e3ecd6702bb80ce26579641d7c50414b7f007be13324f34d214"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/failed-diagnostic-review-v2.json","bytes":1009,"sha256":"4dc2419b7331a803e76b832a240dd0d89bf2976d12c43de96985fdd640cec652"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/failed-key-cleanup-review.json","bytes":1681,"sha256":"6230d71de8156bd60c8e2d1bf24a1c9f0e9ca71fbfbbf72ee0440690c1f8d9e6"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/diagnose-failed-build22r2-private.cjs","bytes":11868,"sha256":"3e6e5680596009d11bc21ff5f6c308bd4459eac8037cbdd124864972fab80684"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/cleanup-failed-build22r2-private.cjs","bytes":7879,"sha256":"49879fbd84722fd83e275af597c339e2969a817483cf4b50c857665c3d7c42f5"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/approval.json","bytes":1314,"sha256":"c1bceaa4e7f97d359049e8c59405837b2bb21e40e3d2e109e929212560f43e62"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/root-dispatch-proof.json","bytes":28123,"sha256":"84eb6357ba5632b40ca99bfe8e7b009f40673509d7c3a3fa6b231a719af1e815"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/root-operation-once.json","bytes":174,"sha256":"e9adb9422eeee12b7d8ff45e5a48cef2accdd1166325a6c6f43d544b0af9528a"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/export-once.json","bytes":118,"sha256":"8e61d4b099dd1d38dde42029f5b73bb8514e4653e13e2ccfdd129a299ed1d140"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/github-dispatch-once.json","bytes":109,"sha256":"e21b1daeafa74eef272dbf1b5c195b16aad69cdca6c402805cebff0efd9a883f"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/failure-diagnostic-once.json","bytes":400,"sha256":"cd5bd3cf1c754f3bec441d36169e44fb6458b8570e266bd6158c17a7490bf984"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/input-52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2.nmae","bytes":7096553,"sha256":"1e69f2a34a05000e0a34e3babf0da8b65c21b4916f6d563f4a43179222806557"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/failed-output-authenticated.nmae","bytes":329185,"sha256":"5dff52a9b480221be0b64096ffa6bf8b17bd59b7b4d19a8b40e1693d8d8e5fea"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/root-authenticated-failure-proof.json","bytes":3162,"sha256":"c8df5714684848928b7df79aedf412a1410b0ba43b0b231e52362c7fa18149f0"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/failed-run-key-cleanup-once.json","bytes":557,"sha256":"f77c25e54a022349e2f6bd0fac2b84890d5a9cd217819f73285acfc8464630ca"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/failed-run-remote-key-deletion.json","bytes":127,"sha256":"98615cc96ad5201310ff9e64e677f0fcac34a6c01c8f08d56ad599c25c8b3be1"},{"file":"C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/failed-run-keys-closed.json","bytes":1086,"sha256":"83eb06a444a06086988e269865eb2ad4d2c5340072985c1fbc2c3007fe21ef15"},
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
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/root-operation-once.json",
    "bytes": 174,
    "sha256": "339bc68e9d63c43b06888c943c45547e3411746d41e045d17939102c95d18576"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/github-dispatch-once.json",
    "bytes": 109,
    "sha256": "1c83b46091f6fb1ceffff4db1b9b8a11a4883674ea6369c4287e987c6b40a447"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/root-dispatch-proof.json",
    "bytes": 28121,
    "sha256": "e90065ff2225e6899818772e9d856552665433f48187c9499d43ac1e6e0c4155"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/dispatch-ack.json",
    "bytes": 433,
    "sha256": "33094d97f24033178207ee4d7009c2d08aeab10839190c7dd84924552fdbd6d7"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/failed-job-official-metadata.json",
    "bytes": 1366,
    "sha256": "9d9a1f26bb5fb69d037d99aa7dbbd1f924f8776220c00dbc0d3c1a210b95a1bc"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/failed-run-key-cleanup-once.json",
    "bytes": 555,
    "sha256": "fbfc53226549c7e2cff88bb73a6ffc6dc6bb822d86b06c9a57eb49dba026e47d"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/failed-run-remote-key-deletion.json",
    "bytes": 127,
    "sha256": "c415bee1a258ce63a0f1224961bf0e67c583e38b9d53a931592d69f5aeab1f8a"
  },
  {
    "file": "C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/failed-run-keys-closed.json",
    "bytes": 1065,
    "sha256": "46f41d3fcb6b0dc48fcc9e85f4a65460a3b090ec39d748e6a81e9d2819834230"
  }
].map(Object.freeze));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const row of ROWS){const b=read(row.file,row.bytes);if(!Buffer.isBuffer(b)||b.length!==row.bytes||sha(b)!==row.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(row.file,b);}return held;}
function holdAll(read){if(require('node:fs').existsSync("C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/key.bin"))throw Error('FAILED_HISTORY_REFUSED');if(require('node:fs').existsSync("C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/key.bin"))throw Error('FAILED_HISTORY_REFUSED');if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map([...require(PREVIOUS).holdAll(read),...hold(read)]);if(held.size!==60)throw Error('FAILED_HISTORY_REFUSED');return held;}
function same(held,read){if(require('node:fs').existsSync("C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-r2-20261021/protected/52cf0224-d4e7-4f6c-ad8a-0503ae4b6be2/key.bin"))throw Error('FAILED_HISTORY_REFUSED');if(require('node:fs').existsSync("C:/Users/runge/.nevermonday-secrets/ios22-engagement-build-preparation-20261021/protected/4fe03c59-9ccf-4eec-b8c2-db10ebe0ec35/key.bin"))throw Error('FAILED_HISTORY_REFUSED');if(!(held instanceof Map)||held.size!==60||typeof read!=='function')throw Error('FAILED_HISTORY_REFUSED');for(const[p,b]of held){const current=read(p,b.length);if(!Buffer.isBuffer(current)||!current.equals(b))throw Error('FAILED_HISTORY_REFUSED');}}
module.exports={OLD_ID,PREVIOUS,ROWS,hold,holdAll,same};
