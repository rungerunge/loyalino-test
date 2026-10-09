'use strict';
// Root-supplied finite descriptors. No default/private input I/O.
const crypto=require('node:crypto');
const OLD_ID='c0a2142a-c51b-41a1-9e9e-8ecbdacba1fd',BASE='C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-context-v2-20261006/protected/'+OLD_ID;
const ROWS=Object.freeze([
 ['root-operation-once.json',257,'51f41dbb00bf541fb919e27836d8dffd347dbbdc079307c2fae413bb0b88fd8f'],
 ['github-dispatch-once.json',109,'e2ec5cbdbc2be7c5ef46c292f60c841ca8acbb71257da6a9b6e3c2681872d624'],
 ['root-dispatch-proof.json',164767,'04df5c4e7886f012b5f12e183ab9b5821175317a60e1baf8b3a39d0659248fc9'],
 ['key-cleanup.json',140,'deabb0371b5bb1569bb242e50b8581c7166c250205f4a0b07873cb8da1fd6e45'],
 ['root-cleanup-f1f33f24-252b-440a-879d-b5430293973b.json',1047,'d2411d859f24c3a3c84d40fa15c544fe0466c96b4e1d2c142d6ffe7256494ef5'],
 ['root-authenticated-failure-proof.json',2423,'289dc58bda1af8c9221c820d2fe9a2d62f2908fe04bf92b21d00bbe4e6d7a75c']
].map(([name,bytes,sha256])=>Object.freeze({file:BASE+'/'+name,bytes,sha256})));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const r of ROWS){const b=read(r.file,r.bytes);if(!Buffer.isBuffer(b)||b.length!==r.bytes||sha(b)!==r.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(r.file,b);}return held;}
function same(held,read){for(const[p,b]of held)if(!read(p,b.length).equals(b))throw Error('FAILED_HISTORY_REFUSED');}
module.exports={OLD_ID,BASE,ROWS,hold,same};
