'use strict';
// Root-supplied finite descriptors only. Import/default never reads protected history.
const crypto=require('node:crypto');
const OLD_ID='f8955263-133c-4d9f-92fe-b915f7722c23',BASE='C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-audit-diagnostic-20261006/protected/'+OLD_ID;
const ROWS=Object.freeze([
 ['root-operation-once.json',257,'f85777571e7c396435702ff2b3f326c8af6fdb161e483faeb8c14deecb68d336'],
 ['github-dispatch-once.json',109,'1101c6e62b3f204c15ef921329bcfeb01a67335d3490090bc3065d2c27977a61'],
 ['root-dispatch-proof.json',172741,'4095e9fa33a787eeafbf527e803a40da29af41169b9a830791b3ffe9ae9b1fc8'],
 ['key-cleanup.json',140,'d0d64f4850af582b5625f9291ae519b878a2f2f8a013ee72ab9af0b8af9cb015'],
 ['root-cleanup-a4b21275-b580-4d0b-b966-cab1ac6d1f83.json',1231,'03ca4031a19d677615fada61d94ac62bcf8f37b068c30cfa3a07191e27d35ef7'],
 ['root-authenticated-failure-proof.json',2526,'5b1c3a93a4ec7511595667364d866491719a0725f37bd993e05e7341a8ae23e8'],
 ['root-status-6694e167-ad04-40e3-a014-05bcad5362e1.json',1758,'dc6ac2856be109bf44fbea788601088097966a09d401cd4fab2e66aa705fb1e5']
].map(([name,bytes,sha256])=>Object.freeze({file:BASE+'/'+name,bytes,sha256})));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const row of ROWS){const b=read(row.file,row.bytes);if(!Buffer.isBuffer(b)||b.length!==row.bytes||sha(b)!==row.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(row.file,b);}return held;}
function holdAll(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map([...require('./failed-operation.cjs').hold(read),...require('./failed-operation-c0a.cjs').hold(read),...hold(read)]);if(held.size!==20)throw Error('FAILED_HISTORY_REFUSED');return held;}
function same(held,read){if(!(held instanceof Map)||held.size!==20||typeof read!=='function')throw Error('FAILED_HISTORY_REFUSED');for(const[p,b]of held)if(!read(p,b.length).equals(b))throw Error('FAILED_HISTORY_REFUSED');}
module.exports={OLD_ID,BASE,ROWS,hold,holdAll,same};
