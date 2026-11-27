// Offline Srun reference vectors, with synthetic credentials only.
// Algorithm reference: Mythologyli/zju-web-login (MIT), see THIRD_PARTY_NOTICES.txt.
import { createHmac, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const alphabet = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA';
const std = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function words(s, length) {
  const out = [];
  for (let i=0;i<s.length;i+=4) out.push(s.charCodeAt(i) | s.charCodeAt(i+1)<<8 | s.charCodeAt(i+2)<<16 | s.charCodeAt(i+3)<<24);
  if (length) out.push(s.length);
  return out;
}
function encode(s,key) {
  const v=words(s,true),k=words(key,false); while(k.length<4) k.push(0);
  const n=v.length-1; let z=v[n],sum=0;
  for(let q=Math.floor(6+52/(n+1));q>0;q--) {
    sum=(sum+0x9e3779b9)>>>0; const e=(sum>>>2)&3;
    for(let p=0;p<=n;p++) {
      const y=v[p===n?0:p+1];
      const m=((z>>>5 ^ y<<2) + ((y>>>3 ^ z<<4) ^ (sum ^ y)) + (k[(p&3)^e] ^ z))>>>0;
      z=v[p]=(v[p]+m)>>>0;
    }
  }
  const bytes=Buffer.alloc(v.length*4); v.forEach((x,i)=>bytes.writeUInt32LE(x>>>0,i*4));
  return bytes.toString('base64').replace(/[A-Za-z0-9+/]/g,c=>alphabet[std.indexOf(c)]);
}
const vectors = [
  {username:'test-user',password:'test-password',ip:'10.1.2.3',acid:'80',token:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'},
  {username:'test-user',password:'测试p&+😀',ip:'10.8.9.10',acid:'3',token:'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'},
].map(v=>{
  const plain=JSON.stringify({username:v.username,password:v.password,ip:v.ip,acid:v.acid,enc_ver:'srun_bx1'});
  const info='{SRBX1}'+encode(plain,v.token);
  const hmd5=createHmac('md5',v.token).update(v.password).digest('hex');
  const joined=[v.username,hmd5,v.acid,v.ip,'200','1',info].map(s=>v.token+s).join('');
  return {...v,info,hmd5,chksum:createHash('sha1').update(joined).digest('hex')};
});
writeFileSync(new URL('./vectors.json',import.meta.url),JSON.stringify(vectors,null,2)+'\n');
console.log('Created two synthetic Srun vectors');
console.log(Buffer.from([0,1,2,253,254,255]).toString('base64').replace(/[A-Za-z0-9+/]/g,c=>alphabet[std.indexOf(c)]));
