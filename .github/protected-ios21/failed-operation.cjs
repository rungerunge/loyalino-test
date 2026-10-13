'use strict';
// Finite Root-supplied history descriptors only. No default/private input I/O.
const crypto=require('node:crypto');
const OLD_ID='004dcd70-4e30-4ef6-97a0-47b984e6b131',BASE='C:/Users/runge/.nevermonday-secrets/ios16-protected-github-macos-source-20261006/protected/'+OLD_ID;
const ROWS=Object.freeze([
 ['root-operation-once.json',257,'ad7069edf1c66db59965af5dc5e21aaef1f97b965aa9d7785e3faa81b01798e9'],
 ['release-continuation-once.json',278,'5cee4359231f581f3108dda54102e2bb29be98870bac36d0cf8290f672d54c8d'],
 ['github-dispatch-once.json',109,'29e2a563f55363585529af54b207a64456b9bb2c5f03fe3b70e0e0d741908ca5'],
 ['root-dispatch-proof.json',26039,'955296e86956e44c2aafcad144194f4211717ffd54ba4b1d94942adf2346264c'],
 ['root-dispatch-continuation-proof.json',133755,'ab278a4989d48849432689f08a994416b1662b4ce7eadd59a79a295af4da6383'],
 ['key-cleanup.json',140,'adb433bed8bbdfde3949722cca633534a6a7cf35fda7459c64512bbe142258c6'],
 ['plugin-failure-classification-0246dd9b-4fe1-4389-a10a-45a205d778fc.json',784,'78aad859ec699c7a04ae855406779860112e84e1a42d48842a64834aee23f5ab']
].map(([name,bytes,sha256])=>Object.freeze({file:BASE+'/'+name,bytes,sha256})));
const ASSETS=Object.freeze({claim:Object.freeze({id:613994137,bytes:933,sha256:'79c1d313bf4f8a8a5174914225db2349328d25daf3233662889e1dcd871f81c4'}),failure:Object.freeze({id:613994591,bytes:5003,sha256:'4126d6cb23e668600c25b99d94b2b06b0bf9cb22ed7b7dc24d663c7b6db45cdf'})});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function hold(read){if(typeof read!=='function')throw Error('FAILED_HISTORY_READER_REQUIRED');const held=new Map();for(const r of ROWS){const b=read(r.file,r.bytes);if(!Buffer.isBuffer(b)||b.length!==r.bytes||sha(b)!==r.sha256)throw Error('FAILED_HISTORY_REFUSED');held.set(r.file,b);}return held;}
function same(held,read){for(const[p,b]of held)if(!read(p,b.length).equals(b))throw Error('FAILED_HISTORY_REFUSED');}
module.exports={OLD_ID,BASE,ROWS,ASSETS,hold,same};
