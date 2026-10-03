// MediCare HMS backend - Node 18+, zero dependencies, JWT roles, JSON-file storage
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,PORT=+E.PORT||3100,DATA=path.join(E.DATA_DIR||__dirname,'data');
fs.mkdirSync(DATA,{recursive:true});
let SECRET=E.JWT_SECRET;if(!SECRET){const f=path.join(DATA,'secret');try{SECRET=fs.readFileSync(f,'utf8')}catch{SECRET=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,SECRET,{mode:0o600})}}
const b64=o=>Buffer.from(typeof o==='string'?o:JSON.stringify(o)).toString('base64url'),sig=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=i=>{const s=b64({alg:'HS256',typ:'JWT'})+'.'+b64({sub:i,exp:Math.floor(Date.now()/1e3)+86400});return s+'.'+sig(s)};
const verify=t=>{try{const[h,p,s]=String(t).split('.'),m=sig(h+'.'+p);if(!s||s.length!==m.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(m)))return null;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp*1e3>Date.now()?o.sub:null}catch{return null}};
const hpw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex'),id=()=>crypto.randomBytes(5).toString('hex');
/* ---------- storage ---------- */
const F=path.join(DATA,'db.json');let db;try{db=JSON.parse(fs.readFileSync(F,'utf8'))}catch{db=null}
const save=()=>{fs.writeFileSync(F+'.tmp',JSON.stringify(db));fs.renameSync(F+'.tmp',F)};
const mkU=(name,email,role,pw)=>{const salt=crypto.randomBytes(16).toString('hex');return{id:id(),name,email,role,salt,hash:hpw(pw,salt),active:true,at:Date.now()}};
if(!db){db={users:[],patients:[],appointments:[],records:[],medicines:[],bills:[],audit:[]};
 [['Admin','admin@hospital.local','admin','Admin@123'],['Dr. Meena','doctor@hospital.local','doctor','Doctor@123'],['Reception Desk','reception@hospital.local','reception','Reception@123'],['Pharmacist','pharmacy@hospital.local','pharmacist','Pharma@123']].forEach(a=>db.users.push(mkU(...a)));
 [['Paracetamol 500mg',200,2,'2028-12-31'],['Amoxicillin 250mg',80,8,'2027-06-30'],['Cetirizine 10mg',8,3,'2027-03-31']].forEach(m=>db.medicines.push({id:id(),name:m[0],stock:m[1],price:m[2],expiry:m[3],at:Date.now()}));save()}
/* ---------- rules ---------- */
const D=/^\d{4}-\d{2}-\d{2}$/,T=/^\d{2}:\d{2}$/,N=v=>v!==''&&v!=null&&isFinite(v)&&+v>=0,ROLES=['admin','doctor','reception','pharmacist'];
const pt=b=>db.patients.some(p=>p.id===b.patientId),NB=['consultation','medicine','other','discount','taxPct'];
const tot=b=>+((+b.consultation+ +b.medicine+ +b.other-+b.discount)*(1+b.taxPct/100)).toFixed(2);
const S={
 patients:{r:'admin,reception,doctor',w:'admin,reception',pick:['name','age','gender','phone','address'],num:['age'],
  chk:b=>!String(b.name||'').trim()?'Name is required':!(N(b.age)&&+b.age<=130)?'Valid age required':!/^\d{10}$/.test(String(b.phone||''))?'Phone must be 10 digits':null},
 appointments:{r:'admin,reception,doctor',w:'admin,reception',pick:['patientId','doctor','date','time','status'],
  chk:(b,x)=>!pt(b)?'Select a patient':!db.users.some(u=>u.id===b.doctor&&u.role==='doctor'&&u.active)?'Select a doctor':!D.test(b.date||'')||!T.test(b.time||'')?'Date and time required':!['Booked','Completed','Cancelled'].includes(b.status)?'Bad status':b.status!=='Cancelled'&&db.appointments.some(a=>a.id!==(x&&x.id)&&a.doctor===b.doctor&&a.date===b.date&&a.time===b.time&&a.status!=='Cancelled')?'Doctor already booked at that time':null},
 records:{r:'doctor',w:'doctor',pick:['patientId','diagnosis','treatment','medicineId','qty'],num:['qty'],
  chk:b=>!pt(b)?'Select a patient':!String(b.diagnosis||'').trim()?'Diagnosis is required':b.medicineId&&!(db.medicines.some(m=>m.id===b.medicineId)&&+b.qty>0)?'Valid medicine and quantity required':null},
 medicines:{r:'admin,pharmacist,doctor',w:'admin,pharmacist',pick:['name','stock','price','expiry'],num:['stock','price'],
  chk:b=>!String(b.name||'').trim()?'Name is required':!(N(b.stock)&&Number.isInteger(+b.stock))?'Stock must be a whole number':!N(b.price)?'Valid price required':!D.test(b.expiry||'')?'Expiry date required':null},
 bills:{r:'admin,reception',w:'admin,reception',pick:['patientId',...NB,'status'],num:NB,
  chk:b=>!pt(b)?'Select a patient':!NB.every(k=>N(b[k]))?'Amounts must be numbers (0 or more)':+b.discount>+b.consultation+ +b.medicine+ +b.other?'Discount is larger than the bill':!['Unpaid','Paid'].includes(b.status)?'Bad status':null},
 users:{r:'admin',w:'admin',pick:['name','email','role','active','password'],
  chk:(b,x)=>!String(b.name||'').trim()?'Name is required':!/^\S+@\S+\.\S+$/.test(b.email||'')?'Valid email required':!ROLES.includes(b.role)?'Bad role':db.users.some(u=>u.email===b.email&&u.id!==(x&&x.id))?'Email already used':(!x||b.password)&&String(b.password||'').length<8?'Password min 8 characters':null}};
const clean=(s,b)=>{const d={};for(const k of s.pick)if(k in b){let v=b[k];if(typeof v==='string')v=v.trim().slice(0,300);if(s.num&&s.num.includes(k))v=(v===''||v==null)?(k==='qty'?'':0):+v;d[k]=v}if('active'in d)d.active=!(d.active===false||d.active==='false');return d};
const pubU=u=>({id:u.id,name:u.name,email:u.email,role:u.role,active:u.active}),log=(u,a,c,i)=>{db.audit.push({u:u.id,name:u.name,a,c,i,at:Date.now()});if(db.audit.length>500)db.audit.shift()};
/* ---------- http ---------- */
const hits=new Map(),limited=(ip,max=10)=>{const n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<6e4);a.push(n);hits.set(ip,a);return a.length>max};
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.json':'application/json','.svg':'image/svg+xml','.css':'text/css','.png':'image/png'};
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e5){no(0);req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{ok({})}})});
const send=(res,c,o)=>{res.writeHead(c,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(o))},deny=res=>send(res,403,{error:'Access denied for your role'});
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
 const url=new URL(req.url,'http://x'),p=url.pathname;
 if(!p.startsWith('/api/')){const root=path.join(__dirname,'public');let f=path.normalize(path.join(root,p==='/'?'index.html':p));if(!f.startsWith(root)||!fs.existsSync(f)||fs.statSync(f).isDirectory()){res.writeHead(404);return res.end('Not found')}res.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream','cache-control':'no-cache'});return fs.createReadStream(f).pipe(res)}
 try{
  if(p==='/api/ping')return send(res,200,{ok:1});
  if(p==='/api/health')return send(res,200,{ok:1,db:'JSON file',users:db.users.length});
  const b=await body(req),m=req.method,ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim(),[c,rid]=p.split('/').slice(2);
  if(p==='/api/login'&&m==='POST'){if(limited(ip))return send(res,429,{error:'Too many attempts. Wait a minute.'});
   const u=db.users.find(x=>x.email===String(b.email||'').trim().toLowerCase()&&x.active);
   if(!u||!crypto.timingSafeEqual(Buffer.from(hpw(String(b.password||''),u.salt)),Buffer.from(u.hash)))return send(res,401,{error:'Wrong email or password.'});
   return send(res,200,{token:sign(u.id),user:pubU(u)})}
  const sub=verify((req.headers.authorization||'').replace('Bearer ','')),u=db.users.find(x=>x.id===sub&&x.active);if(!u)return send(res,401,{error:'Please sign in again.'});
  if(p==='/api/me')return send(res,200,{user:pubU(u)});
  if(p==='/api/doctors')return send(res,200,db.users.filter(x=>x.role==='doctor'&&x.active).map(x=>({id:x.id,name:x.name})));
  if(p==='/api/stats'){if(u.role!=='admin')return deny(res);const td=new Date().toISOString().slice(0,10),lim=new Date(Date.now()+90*864e5).toISOString().slice(0,10);
   return send(res,200,{patients:db.patients.length,today:db.appointments.filter(a=>a.date===td&&a.status!=='Cancelled').length,revenue:+db.bills.filter(x=>x.status==='Paid').reduce((s,x)=>s+x.total,0).toFixed(2),unpaid:db.bills.filter(x=>x.status==='Unpaid').length,low:db.medicines.filter(x=>x.stock<=10).length,expiring:db.medicines.filter(x=>x.expiry<=lim).length})}
  if(p==='/api/audit'){if(u.role!=='admin')return deny(res);return send(res,200,db.audit.slice(-100).reverse())}
  if(p==='/api/prescriptions'){if(!['admin','pharmacist','doctor'].includes(u.role))return deny(res);
   return send(res,200,db.records.filter(r=>r.medicineId).map(r=>({id:r.id,patient:(db.patients.find(x=>x.id===r.patientId)||{}).name,medicine:(db.medicines.find(x=>x.id===r.medicineId)||{}).name,qty:r.qty,dispensed:r.dispensed})).reverse())}
  if(p==='/api/dispense'&&m==='POST'){if(u.role!=='pharmacist')return deny(res);const r=db.records.find(x=>x.id===b.id);if(!r||!r.medicineId)return send(res,404,{error:'Prescription not found'});
   if(r.dispensed)return send(res,409,{error:'Already dispensed'});const md=db.medicines.find(x=>x.id===r.medicineId);if(!md)return send(res,404,{error:'Medicine not found'});
   if(md.stock<r.qty)return send(res,409,{error:'Insufficient stock ('+md.stock+' left)'});md.stock-=r.qty;r.dispensed=true;log(u,'dispense','records',r.id);save();return send(res,200,{ok:1})}
  const s=S[c];if(!s)return send(res,404,{error:'Not found'});const can=k=>s[k].split(',').includes(u.role);
  if(m==='GET'&&!rid){if(!can('r'))return deny(res);let L=db[c];if(c==='appointments'&&u.role==='doctor')L=L.filter(a=>a.doctor===u.id);return send(res,200,c==='users'?L.map(pubU):L)}
  if(!can('w'))return deny(res);
  if(m==='POST'&&!rid){const d=clean(s,b);if(c==='appointments'&&!d.status)d.status='Booked';if(c==='bills'&&!d.status)d.status='Unpaid';if(c==='users'&&d.active===undefined)d.active=true;
   const er=s.chk(d,null);if(er)return send(res,400,{error:er});const o={id:id(),...d,at:Date.now()};
   if(c==='records'){o.doctor=u.id;o.dispensed=false}if(c==='bills')o.total=tot(o);
   if(c==='users'){o.salt=crypto.randomBytes(16).toString('hex');o.hash=hpw(d.password,o.salt);delete o.password}
   db[c].push(o);log(u,'create',c,o.id);save();return send(res,200,c==='users'?pubU(o):o)}
  const x=db[c].find(i=>i.id===rid);if(!x)return send(res,404,{error:'Record not found'});
  if(m==='PUT'){if(c==='bills'&&x.status==='Paid')return send(res,409,{error:'A paid bill cannot be edited'});if(c==='records'&&x.dispensed)return send(res,409,{error:'Dispensed record is locked'});
   const d=clean(s,b),n={...x,...d};if(c==='users'&&x.id===u.id&&(d.active===false||(d.role&&d.role!==x.role)))return send(res,400,{error:'You cannot disable or change your own role'});
   const er=s.chk(n,x);if(er)return send(res,400,{error:er});Object.assign(x,d);
   if(c==='users'){delete x.password;if(d.password){x.salt=crypto.randomBytes(16).toString('hex');x.hash=hpw(d.password,x.salt)}}if(c==='bills')x.total=tot(x);
   log(u,'update',c,x.id);save();return send(res,200,c==='users'?pubU(x):x)}
  if(m==='DELETE'){if(c==='bills'&&x.status==='Paid')return send(res,409,{error:'A paid bill cannot be deleted'});if(c==='users'&&x.id===u.id)return send(res,400,{error:'You cannot delete yourself'});
   if(c==='patients'&&['appointments','records','bills'].some(k=>db[k].some(i=>i.patientId===rid)))return send(res,409,{error:'Patient has linked appointments, records or bills'});
   db[c]=db[c].filter(i=>i.id!==rid);log(u,'delete',c,rid);save();return send(res,200,{ok:1})}
  send(res,404,{error:'Not found'})}catch(x){console.error('[ERROR]',req.method,p,x&&x.message||x);send(res,500,{error:'Server error'})}});
server.on('error',e=>{console.error(e.code==='EADDRINUSE'?'Port '+PORT+' already in use. Close the old server first.':e);process.exit(1)});
server.listen(PORT,'0.0.0.0',()=>console.log('\n  >>> MediCare HMS running: http://localhost:'+PORT+'  <<<\n'));
process.on('uncaughtException',e=>console.error('[ERROR-kept-running]',e));
