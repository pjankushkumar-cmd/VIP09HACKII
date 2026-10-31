const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=Number(process.env.PORT||3000),ADMIN_SECRET=process.env.ADMIN_SECRET||'';
const DATA_FILE=process.env.DATA_FILE||(fs.existsSync('/var/data')?'/var/data/hackii-data.json':path.join(__dirname,'data','hackii-data.json'));
const PUBLIC_DIR=path.join(__dirname,'public'),USER_COOKIE='hackii_session',ADMIN_COOKIE='hackii_admin';
const SESSION_TTL=30*86400000,ONLINE_WINDOW=90000;
if(!ADMIN_SECRET||ADMIN_SECRET.length<16){console.error('FATAL: Set ADMIN_SECRET in Render Environment (minimum 16 characters).');process.exit(1)}
const fresh=()=>({keys:[],sessions:[],adminSessions:[],signal:null,rounds:[]});
function load(){try{return {...fresh(),...JSON.parse(fs.readFileSync(DATA_FILE,'utf8'))}}catch{return fresh()}}
let db=load();
function save(){fs.mkdirSync(path.dirname(DATA_FILE),{recursive:true});const t=DATA_FILE+'.tmp';fs.writeFileSync(t,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(t,DATA_FILE)}
const sha=x=>crypto.createHash('sha256').update(x).digest('hex'),token=()=>crypto.randomBytes(32).toString('base64url');
function equal(a,b){const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)}
function getCookies(req){const o={};for(const p of(req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)o[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}return o}
function setCookie(n,v,age){return `${n}=${encodeURIComponent(v)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${age}${process.env.NODE_ENV==='production'?'; Secure':''}`}
const clearCookie=n=>`${n}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`;
function send(res,status,data,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(data))}
function readBody(req){return new Promise((ok,no)=>{let s='';req.on('data',c=>{s+=c;if(s.length>16000){no(Error('Request too large'));req.destroy()}});req.on('end',()=>{try{ok(s?JSON.parse(s):{})}catch{no(Error('Invalid JSON'))}});req.on('error',no)})}
function getMember(req){const t=getCookies(req)[USER_COOKIE];if(!t)return null;const ss=db.sessions.find(s=>s.tokenHash===sha(t)&&s.expiresAt>Date.now());if(!ss)return null;const k=db.keys.find(k=>k.id===ss.keyId&&!k.revoked&&k.expiresAt>Date.now());return k?{session:ss,key:k}:null}
function isAdmin(req){const t=getCookies(req)[ADMIN_COOKIE];return !!t&&db.adminSessions.some(s=>s.tokenHash===sha(t)&&s.expiresAt>Date.now())}
function needMember(req,res){const x=getMember(req);if(!x)send(res,401,{error:'Please login with a valid key.'});return x}
function needAdmin(req,res){if(!isAdmin(req)){send(res,401,{error:'Admin login required.'});return false}return true}
function clean(){const n=Date.now();db.sessions=db.sessions.filter(s=>s.expiresAt>n&&db.keys.some(k=>k.id===s.keyId&&!k.revoked&&k.expiresAt>n));db.adminSessions=db.adminSessions.filter(s=>s.expiresAt>n)}
function hint(k){return k.slice(0,4)+'••••'+k.slice(-4)}

function chachaUniform(max){
 const key=crypto.randomBytes(32),iv=crypto.randomBytes(16);
 const cipher=crypto.createCipheriv('chacha20',key,iv);
 const stream=cipher.update(Buffer.alloc(256));
 const limit=Math.floor(0x100000000/max)*max;
 let offset=0;
 function u32(){if(offset+4>stream.length)throw Error('ChaCha20 stream exhausted');const v=stream.readUInt32LE(offset);offset+=4;return v}
 let v;do{v=u32()}while(v>=limit);return v%max;
}
function makeSharedPick(){
 const side=chachaUniform(2)===0?'SMALL':'BIG';
 const low=side==='SMALL'?0:5,chosen=[];
 while(chosen.length<2){const n=low+chachaUniform(5);if(!chosen.includes(n))chosen.push(n)}
 return {prediction:side,numbers:chosen,rng:'ChaCha20'};
}
const HISTORY_API='https://draw.ar-lottery01.com/WinGo/WinGo_1M/GetHistoryIssuePage.json';
let apiCache=null,apiCacheAt=0,apiFetchPromise=null;
async function getOfficialHistory(){
 const now=Date.now();
 if(apiCache&&now-apiCacheAt<2500)return apiCache;
 if(apiFetchPromise)return apiFetchPromise;
 apiFetchPromise=(async()=>{
   const response=await fetch(HISTORY_API+'?t='+Date.now(),{signal:AbortSignal.timeout(9000),headers:{'Accept':'application/json'}});
   if(!response.ok)throw Error('Official result API HTTP '+response.status);
   const json=await response.json();
   const list=json&&json.data&&Array.isArray(json.data.list)?json.data.list:null;
   if(!list||!list.length)throw Error('Official result API returned no history');
   apiCache={list};apiCacheAt=Date.now();return apiCache;
 })();
 try{return await apiFetchPromise}finally{apiFetchPromise=null}
}
async function getSharedSignal(){
 const {list}=await getOfficialHistory();
 const latest=list[0],issue=String(latest.issueNumber),actualNumber=Number(latest.number);
 if(!Number.isInteger(actualNumber)||actualNumber<0||actualNumber>9)throw Error('Invalid official API number');
 if(!db.signal||String(db.signal.sourceIssue)!==issue){
   if(db.signal&&String(db.signal.upcomingIssue)===issue){
     const previous=db.signal,actualSide=actualNumber>=5?'BIG':'SMALL';
     const win=previous.prediction===actualSide;
     const jackpot=win&&previous.numbers.includes(actualNumber);
     db.rounds.unshift({issue,prediction:previous.prediction,numbers:previous.numbers,actualNumber,actualSide,win,jackpot,settledAt:Date.now(),rng:'ChaCha20'});
     db.rounds=db.rounds.slice(0,100);
   }
   const pick=makeSharedPick();
   db.signal={sourceIssue:issue,upcomingIssue:(BigInt(issue)+1n).toString(),...pick,generatedAt:Date.now()};
   save();
 }
 return {list,signal:db.signal,rounds:db.rounds.slice(0,30),apiUpdatedAt:apiCacheAt};
}

function staticFile(res,p){const f=path.resolve(PUBLIC_DIR,p==='/'?'index.html':'.'+p);if(!f.startsWith(PUBLIC_DIR+path.sep)&&f!==path.join(PUBLIC_DIR,'index.html'))return send(res,403,{error:'Forbidden'});fs.readFile(f,(e,d)=>{if(e){fs.readFile(path.join(PUBLIC_DIR,'index.html'),(x,b)=>{if(x)return send(res,404,{error:'Not found'});res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end(b)});return}const ext=path.extname(f),type=ext==='.html'?'text/html; charset=utf-8':ext==='.css'?'text/css':ext==='.js'?'text/javascript':'application/octet-stream';res.writeHead(200,{'Content-Type':type,'Cache-Control':ext==='.html'?'no-store':'public,max-age=3600'});res.end(d)})}
async function route(req,res){
 const p=new URL(req.url,'http://localhost').pathname;
 if(req.method==='GET'&&p==='/health')return send(res,200,{ok:true});
 if(req.method==='POST'&&p==='/api/login'){
  const b=await readBody(req),k=String(b.key||'').trim();if(k.length<8||k.length>100)return send(res,400,{error:'Invalid login key.'});
  clean();const r=db.keys.find(x=>!x.revoked&&x.expiresAt>Date.now()&&equal(x.keyHash,sha(k)));if(!r)return send(res,401,{error:'Invalid or expired login key.'});
  const t=token(),n=Date.now();db.sessions=db.sessions.filter(s=>s.keyId!==r.id);db.sessions.push({id:crypto.randomUUID(),keyId:r.id,tokenHash:sha(t),createdAt:n,startedAt:n,lastSeen:n,lastCountedAt:n,expiresAt:n+SESSION_TTL,deviceId:null,userAgent:'',platform:'',language:'',screen:''});r.loginCount=(r.loginCount||0)+1;r.lastLoginAt=n;save();return send(res,200,{ok:true},{'Set-Cookie':setCookie(USER_COOKIE,t,SESSION_TTL/1000)});
 }
 if(req.method==='POST'&&p==='/api/logout'){const x=getMember(req);if(x){db.sessions=db.sessions.filter(s=>s.id!==x.session.id);save()}return send(res,200,{ok:true},{'Set-Cookie':clearCookie(USER_COOKIE)})}
 if(req.method==='GET'&&p==='/api/me'){const x=getMember(req);return send(res,200,{authenticated:!!x,member:x?{label:x.key.label,expiresAt:x.key.expiresAt}:null})}
 if(req.method==='POST'&&p==='/api/heartbeat'){const x=needMember(req,res);if(!x)return;const b=await readBody(req),n=Date.now(),gap=n-(x.session.lastCountedAt||n);if(gap>0&&gap<=ONLINE_WINDOW*2)x.key.totalOnlineSeconds=(x.key.totalOnlineSeconds||0)+Math.floor(gap/1000);x.session.lastSeen=n;x.session.lastCountedAt=n;x.key.lastSeen=n;x.session.deviceId=String(b.deviceId||x.session.deviceId||'').slice(0,100);x.session.userAgent=String(b.userAgent||'').slice(0,240);x.session.platform=String(b.platform||'').slice(0,80);x.session.language=String(b.language||'').slice(0,30);x.session.screen=String(b.screen||'').slice(0,30);save();return send(res,200,{ok:true})}
 if(req.method==='GET'&&p==='/api/signal'){if(!needMember(req,res))return;try{return send(res,200,await getSharedSignal())}catch(e){console.error('Signal sync:',e.message);return send(res,503,{error:'Official result API is temporarily unavailable. No local prediction was generated.'})}}
 if(req.method==='POST'&&p==='/api/admin/login'){const b=await readBody(req);if(!equal(b.secret||'',ADMIN_SECRET))return send(res,401,{error:'Incorrect admin secret.'});const t=token(),n=Date.now();db.adminSessions.push({tokenHash:sha(t),createdAt:n,expiresAt:n+8*3600000});save();return send(res,200,{ok:true},{'Set-Cookie':setCookie(ADMIN_COOKIE,t,28800)})}
 if(req.method==='GET'&&p==='/api/admin/me')return send(res,200,{admin:isAdmin(req)});
 if(req.method==='POST'&&p==='/api/admin/logout'){const t=getCookies(req)[ADMIN_COOKIE]||'';db.adminSessions=db.adminSessions.filter(s=>s.tokenHash!==sha(t));save();return send(res,200,{ok:true},{'Set-Cookie':clearCookie(ADMIN_COOKIE)})}
 if(req.method==='GET'&&p==='/api/admin/overview'){if(!needAdmin(req,res))return;clean();const n=Date.now(),members=db.keys.map(k=>{const s=db.sessions.filter(x=>x.keyId===k.id&&x.expiresAt>n).sort((a,b)=>b.lastSeen-a.lastSeen)[0]||null;const online=!!(s&&n-s.lastSeen<=ONLINE_WINDOW);return{id:k.id,label:k.label,keyHint:k.keyHint,expiresAt:k.expiresAt,totalOnlineSeconds:k.totalOnlineSeconds||0,lastSeen:k.lastSeen||null,loginCount:k.loginCount||0,online,sessionStartedAt:s?s.startedAt:null,sessionDurationSeconds:s&&online?Math.max(0,Math.floor((n-s.startedAt)/1000)):0,deviceId:s?s.deviceId:null,deviceInfo:s?[s.platform,s.userAgent,s.screen,s.language].filter(Boolean).join(' | '):null}}).sort((a,b)=>(b.online?1:0)-(a.online?1:0)||(b.totalOnlineSeconds-a.totalOnlineSeconds));save();return send(res,200,{stats:{totalKeys:db.keys.length,activeKeys:db.keys.filter(k=>k.expiresAt>n&&!k.revoked).length,onlineNow:members.filter(m=>m.online).length,totalMembers:db.keys.length},members,sharedSignal:db.signal})}
 if(req.method==='POST'&&p==='/api/admin/keys'){if(!needAdmin(req,res))return;const b=await readBody(req),days=Number(b.days);if(!Number.isInteger(days)||days<1||days>365)return send(res,400,{error:'Validity must be 1–365 days.'});const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';let raw='HACKII-';for(let i=0;i<16;i++)raw+=chars[crypto.randomInt(chars.length)];const n=Date.now(),r={id:crypto.randomUUID(),keyHash:sha(raw),keyHint:hint(raw),label:String(b.label||'').slice(0,40),createdAt:n,expiresAt:n+days*86400000,totalOnlineSeconds:0,loginCount:0,lastSeen:null,revoked:false};db.keys.push(r);save();return send(res,201,{ok:true,key:raw,memberId:r.id,expiresAt:r.expiresAt})}
 if(req.method==='DELETE'&&p.startsWith('/api/admin/keys/')){if(!needAdmin(req,res))return;const id=decodeURIComponent(p.split('/').pop()),k=db.keys.find(x=>x.id===id);if(!k)return send(res,404,{error:'Key not found.'});k.revoked=true;db.sessions=db.sessions.filter(s=>s.keyId!==id);save();return send(res,200,{ok:true})}
 if(p.startsWith('/api/'))return send(res,404,{error:'API endpoint not found.'});
 staticFile(res,p);
}
http.createServer((req,res)=>route(req,res).catch(e=>{console.error(e);if(!res.headersSent)send(res,500,{error:'Server error.'})})).listen(PORT,'0.0.0.0',()=>console.log(`HACKII PANEL listening on ${PORT}; data=${DATA_FILE}`));
