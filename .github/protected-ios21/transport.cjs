'use strict';
const https=require('node:https'),P=require('./policy.cjs'),Q=require('./export-query.cjs');
const MAX_BYTES=1048576,DEADLINE_MS=30000;
function query(kind,identifier,auth,deadline,ports={}){
 const now=ports.now||Date.now,http=ports.https||https,timer=ports.setTimeout||setTimeout,clear=ports.clearTimeout||clearTimeout;
 if(!P.exact(auth,['type','value'])||!['accessToken','sessionSecret'].includes(auth.type)||typeof auth.value!=='string'||auth.value.length<1||auth.value.length>4096||/[\x00-\x20\x7f]/.test(auth.value)||!Number.isSafeInteger(deadline)||deadline<=now()||deadline-now()>DEADLINE_MS)P.fail();
 const body=Buffer.from(JSON.stringify(Q.request(kind,identifier)));
 return new Promise((resolve,reject)=>{let req,res,t,done=false,total=0;const pieces=[];
  const finish=(bad,value)=>{if(done)return;done=true;if(t!==undefined)clear(t);if(bad){if(req)req.destroy();if(res)res.destroy();reject(Error('PROTECTED_SIGNER_QUERY_REFUSED'));}else resolve(value);};
  t=timer(()=>finish(true),deadline-now());
  try{req=http.request({protocol:'https:',hostname:'api.expo.dev',port:443,path:'/graphql',method:'POST',rejectUnauthorized:true,agent:false,headers:{'content-type':'application/json',accept:'application/json','accept-encoding':'identity','content-length':body.length,...(auth.type==='accessToken'?{authorization:'Bearer '+auth.value}:{'expo-session':auth.value})}},r=>{
   res=r;if(done){r.destroy();return;}if(now()>=deadline||r.statusCode!==200||r.headers.location!==undefined||r.headers['content-encoding']!==undefined&&r.headers['content-encoding']!=='identity'||typeof r.headers['content-type']!=='string'||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(r.headers['content-type'])||r.headers['content-length']!==undefined&&(!/^[1-9][0-9]{0,6}$/.test(r.headers['content-length'])||Number(r.headers['content-length'])>MAX_BYTES)){finish(true);return;}
   r.on('data',b=>{if(done)return;if(!Buffer.isBuffer(b)||now()>=deadline||(total+=b.length)>MAX_BYTES){finish(true);return;}pieces.push(b);});
   r.on('end',()=>{if(done)return;try{const b=Buffer.concat(pieces),s=b.toString('utf8');if(now()>=deadline||b.length<1||!Buffer.from(s).equals(b)||r.headers['content-length']!==undefined&&Number(r.headers['content-length'])!==total)P.fail();const v=JSON.parse(s);if(!P.exact(v,['data']))P.fail();finish(false,v.data);}catch{finish(true);}});
   r.on('error',()=>finish(true));r.on('aborted',()=>finish(true));
  });req.on('error',()=>finish(true));req.end(body);}catch{finish(true);}
 });
}
module.exports={MAX_BYTES,DEADLINE_MS,query};
