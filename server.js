require('dotenv').config();
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const compression=require('compression'),express=require('express'),http=require('http'),{Server}=require('socket.io');
const bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),cookieParser=require('cookie-parser'),cookieLib=require('cookie');
const multer=require('multer'),nodemailer=require('nodemailer'),{OAuth2Client}=require('google-auth-library');

const {PORT=3000,JWT_SECRET='change-me',GOOGLE_CLIENT_ID='',BASE_URL='http://localhost:3000',DATA_DIR=path.join(__dirname,'data')}=process.env;
const ADMIN=(process.env.ADMIN_EMAIL||'kati05256@gmail.com').toLowerCase();
fs.mkdirSync(path.join(DATA_DIR,'uploads'),{recursive:true});
const DB_FILE=path.join(DATA_DIR,'db.json');
let db={users:[],listings:[],offers:[],buys:[],convos:[],messages:[]};
// Optional free Postgres (Neon/Supabase): set DATABASE_URL. Without it, a JSON file in DATA_DIR is used.
let pool=null;
if(process.env.DATABASE_URL){const {Pool}=require('pg');pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)?false:{rejectUnauthorized:false},max:3})}
async function loadDb(){
  if(pool){
    await pool.query('create table if not exists kv(k text primary key,v jsonb not null)');
    await pool.query('create table if not exists images(id text primary key,mime text not null,data bytea not null)');
    const r=await pool.query("select v from kv where k='db'");if(r.rows[0])db={...db,...r.rows[0].v};
    console.log('Using Postgres database');
  }else{if(fs.existsSync(DB_FILE))db={...db,...JSON.parse(fs.readFileSync(DB_FILE))};console.log('Using JSON file in '+DATA_DIR)}
}
async function flush(){
  if(pool)return pool.query("insert into kv(k,v) values('db',$1) on conflict(k) do update set v=excluded.v",[JSON.stringify(db)]).catch(e=>console.error('DB save failed',e.message));
  fs.writeFileSync(DB_FILE+'.tmp',JSON.stringify(db));fs.renameSync(DB_FILE+'.tmp',DB_FILE);
}
let st;const save=()=>{clearTimeout(st);st=setTimeout(flush,150)};
process.on('SIGTERM',async()=>{await flush();process.exit(0)});
const id=()=>crypto.randomUUID();

// ---------- mail ----------
const mailer=process.env.SMTP_HOST?nodemailer.createTransport({host:process.env.SMTP_HOST,port:+(process.env.SMTP_PORT||587),secure:+process.env.SMTP_PORT===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
async function mail(to,subject,html){
  if(!mailer){console.log('[MAIL not configured]',to,subject,html);return}
  await mailer.sendMail({from:process.env.SMTP_FROM||process.env.SMTP_USER,to,subject,html});
}

// ---------- app / auth ----------
const app=express(),server=http.createServer(app),io=new Server(server);
app.set('trust proxy',1);
app.use(compression(),express.json(),cookieParser());
if(pool)app.get('/uploads/:name',async(req,res)=>{
  try{const r=await pool.query('select mime,data from images where id=$1',[req.params.name]);
    if(!r.rows[0])return res.sendStatus(404);
    res.set({'Content-Type':r.rows[0].mime,'Cache-Control':'public, max-age=2592000, immutable'}).send(r.rows[0].data)}catch{res.sendStatus(500)}});
app.use('/uploads',express.static(path.join(DATA_DIR,'uploads'),{maxAge:'30d',immutable:true}));
app.use(express.static(path.join(__dirname,'public')));
const userById=i=>db.users.find(u=>u.id===i);
const byName=n=>{n=String(n||'').replace(/^@/,'').toLowerCase();return db.users.find(u=>u.username.toLowerCase()===n)};
const pub=u=>({id:u.id,username:u.username,role:u.role,email:u.email});
const setCk=(res,u)=>res.cookie('tk',jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'30d'}),{httpOnly:true,sameSite:'lax',secure:BASE_URL.startsWith('https'),maxAge:2592e6});
function auth(req,res,next){try{req.user=userById(jwt.verify(req.cookies.tk,JWT_SECRET).id)}catch{}
  if(!req.user)return res.status(401).json({error:'Please log in'});next()}
const adminOnly=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Admin only'});
const validName=n=>/^[a-zA-Z0-9_]{3,20}$/.test(n||'');
const bad=(res,m,c=400)=>res.status(c).json({error:m});
const isOnline=u=>io.sockets.adapter.rooms.has('u:'+u);
const toAdmins=(ev,d)=>db.users.filter(u=>u.role==='admin').forEach(a=>io.to('u:'+a.id).emit(ev,d));

app.get('/api/config',(q,r)=>r.json({googleClientId:GOOGLE_CLIENT_ID}));
app.get('/api/me',auth,(req,res)=>res.json(pub(req.user)));
app.post('/api/logout',(q,res)=>{res.clearCookie('tk');res.json({ok:true})});

app.post('/api/signup',async(req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase(),{username,password}=req.body;
  if(!/^\S+@\S+\.\S+$/.test(email))return bad(res,'Invalid email');
  if(!validName(username))return bad(res,'Username: 3-20 letters, numbers or _');
  if(username.toLowerCase()==='admin'||byName(username))return bad(res,'Username taken');
  if(String(password||'').length<8)return bad(res,'Password must be 8+ characters');
  if(email===ADMIN)return bad(res,'Admin must sign in with Google');
  if(db.users.some(u=>u.email===email))return bad(res,'Email already registered');
  const vtoken=crypto.randomBytes(24).toString('hex');
  const u={id:id(),email,username,hash:await bcrypt.hash(password,10),role:'user',verified:false,vtoken,created:Date.now()};
  db.users.push(u);save();
  try{await mail(email,'Verify your email',`<p>Welcome to CardVault, ${username}!</p><p><a href="${BASE_URL}/api/verify?token=${vtoken}">Click here to verify your email</a></p>`)}
  catch(e){console.error(e);db.users=db.users.filter(x=>x!==u);save();return bad(res,'Could not send verification email',500)}
  res.json({ok:true});
});
app.get('/api/verify',(req,res)=>{
  const u=req.query.token&&db.users.find(u=>u.vtoken===req.query.token);
  if(!u)return res.send('Invalid or already used link.');
  u.verified=true;delete u.vtoken;save();res.redirect('/?verified=1');
});
app.post('/api/login',async(req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase();
  const u=db.users.find(u=>u.email===email&&u.hash);
  if(!u||!(await bcrypt.compare(String(req.body.password||''),u.hash)))return bad(res,'Wrong email or password');
  if(!u.verified)return bad(res,'Please verify your email first (check your inbox)',403);
  setCk(res,u);res.json(pub(u));
});

const gc=new OAuth2Client(GOOGLE_CLIENT_ID);
app.post('/api/google',async(req,res)=>{
  try{
    const p=(await gc.verifyIdToken({idToken:req.body.credential,audience:GOOGLE_CLIENT_ID})).getPayload();
    if(!p.email_verified)return bad(res,'Google email not verified');
    const email=p.email.toLowerCase();let u=db.users.find(u=>u.email===email);
    if(!u){
      if(email===ADMIN){u={id:id(),email,username:'admin',role:'admin',verified:true,created:Date.now()};db.users.push(u);save()}
      else return res.json({needUsername:true,pending:jwt.sign({email},JWT_SECRET,{expiresIn:'15m'})});
    }else if(email===ADMIN&&u.role!=='admin'){u.role='admin';u.username='admin';save()}
    if(!u.verified){u.verified=true;save()}
    setCk(res,u);res.json(pub(u));
  }catch(e){console.error(e.message);bad(res,'Google sign-in failed')}
});
app.post('/api/google/username',(req,res)=>{
  try{
    const {email}=jwt.verify(req.body.pending,JWT_SECRET),n=req.body.username;
    if(email===ADMIN)return bad(res,'Not allowed');
    if(!validName(n))return bad(res,'Username: 3-20 letters, numbers or _');
    if(n.toLowerCase()==='admin'||byName(n))return bad(res,'Username taken');
    if(db.users.some(u=>u.email===email))return bad(res,'Account exists');
    const u={id:id(),email,username:n,role:'user',verified:true,created:Date.now()};
    db.users.push(u);save();setCk(res,u);res.json(pub(u));
  }catch{bad(res,'Session expired, sign in with Google again')}
});

app.delete('/api/me',auth,(req,res)=>{
  const u=req.user;if(u.role==='admin')return bad(res,'The admin account cannot be deleted');
  db.users=db.users.filter(x=>x.id!==u.id);
  db.offers=db.offers.filter(o=>o.userId!==u.id||o.status==='completed');
  db.buys=db.buys.filter(b=>b.userId!==u.id||b.status==='completed');
  const mine=db.convos.filter(c=>c.a===u.id||c.b===u.id).map(c=>c.id);
  db.convos=db.convos.filter(c=>!mine.includes(c.id));db.messages=db.messages.filter(m=>!mine.includes(m.convoId));
  save();res.clearCookie('tk');res.json({ok:true});
});

// ---------- listings ----------
const upload=multer({storage:pool?multer.memoryStorage():multer.diskStorage({destination:path.join(DATA_DIR,'uploads'),
  filename:(q,f,cb)=>cb(null,id()+path.extname(f.originalname).toLowerCase().replace(/[^.a-z0-9]/g,''))}),
  limits:{fileSize:8e6},fileFilter:(q,f,cb)=>cb(null,/^image\//.test(f.mimetype))});
app.get('/api/listings',(q,res)=>res.json(db.listings.filter(l=>!l.removed)));
app.post('/api/listings',auth,adminOnly,upload.single('photo'),async(req,res)=>{
  const {title,description,price}=req.body;
  if(!req.file||!title||!(+price>0))return bad(res,'Photo, title and price are required');
  let fname=req.file.filename;
  if(pool){fname=id()+path.extname(req.file.originalname).toLowerCase().replace(/[^.a-z0-9]/g,'');
    try{await pool.query('insert into images(id,mime,data) values($1,$2,$3)',[fname,req.file.mimetype,req.file.buffer])}catch(e){console.error(e.message);return bad(res,'Could not save photo',500)}}
  const l={id:id(),title:title.slice(0,100),description:String(description||'').slice(0,2000),price:+price,image:'/uploads/'+fname,sold:false,created:Date.now()};
  db.listings.unshift(l);save();io.emit('listings:changed');res.json(l);
});
app.post('/api/listings/:id/sold',auth,adminOnly,(req,res)=>{
  const l=db.listings.find(x=>x.id===req.params.id&&!x.removed);
  if(!l||l.sold)return bad(res,'Listing not found or already sold');
  const bn=String(req.body.buyer||'').trim(),b=bn?byName(bn):null;
  if(bn&&!b)return bad(res,'Buyer username not found');
  Object.assign(l,{sold:true,soldAt:Date.now(),soldPrice:+req.body.price||l.price,buyerId:b?b.id:null,buyerName:b?b.username:null});
  for(const x of [...db.offers,...db.buys])if(x.listingId===l.id&&['pending','accepted','won'].includes(x.status))x.status=(b&&x.userId===b.id)?'completed':'closed';
  save();io.emit('listings:changed');
  if(b)io.to('u:'+b.id).emit('notify',{to:'purchases',text:`"${l.title}" is now yours! See the Purchases tab.`});
  res.json(l);
});
app.delete('/api/listings/:id',auth,adminOnly,(req,res)=>{
  const l=db.listings.find(x=>x.id===req.params.id);
  if(!l)return bad(res,'Not found');
  if(!l.sold)return bad(res,'Mark the card as SOLD before removing it');
  l.removed=true;save();io.emit('listings:changed');res.json({ok:true});
});
app.post('/api/listings/:id/offer',auth,(req,res)=>{
  const l=db.listings.find(x=>x.id===req.params.id&&!x.removed),amount=+req.body.amount;
  if(!l||l.sold)return bad(res,'Card not available');
  if(req.user.role==='admin')return bad(res,'Admin cannot make offers');
  if(!(amount>0))return bad(res,'Enter a valid amount');
  db.offers.push({id:id(),listingId:l.id,title:l.title,userId:req.user.id,username:req.user.username,amount,status:'pending',created:Date.now()});save();
  toAdmins('notify',{to:'sells',text:`@${req.user.username} offered $${amount} for "${l.title}"`});res.json({ok:true});
});
app.post('/api/offers/:id',auth,adminOnly,(req,res)=>{
  const o=db.offers.find(o=>o.id===req.params.id),s=req.body.status;
  if(!o||!['accepted','declined'].includes(s))return bad(res,'Bad request');
  o.status=s;save();io.to('u:'+o.userId).emit('notify',{to:'purchases',text:`Your offer of $${o.amount} on "${o.title}" was ${s}.`});res.json(o);
});
app.get('/api/admin/overview',auth,adminOnly,(q,res)=>res.json({listings:db.listings,offers:db.offers,buys:db.buys}));
app.get('/api/purchases',auth,(req,res)=>{const i=req.user.id;
  res.json({bought:db.listings.filter(l=>l.buyerId===i),offers:db.offers.filter(o=>o.userId===i),buys:db.buys.filter(b=>b.userId===i)})});

// ---------- buy + rock paper scissors ----------
const games={};
app.post('/api/listings/:id/buy',auth,(req,res)=>{
  const l=db.listings.find(x=>x.id===req.params.id&&!x.removed),u=req.user;
  if(!l||l.sold)return bad(res,'Card not available');
  if(u.role==='admin')return bad(res,'Admin cannot buy');
  if(db.buys.some(b=>b.listingId===l.id&&b.userId===u.id&&['pending','won'].includes(b.status)))return bad(res,'You already requested this card');
  db.buys.push({id:id(),listingId:l.id,title:l.title,userId:u.id,username:u.username,status:'pending',created:Date.now()});save();
  toAdmins('notify',{to:'sells',text:`@${u.username} wants to BUY "${l.title}"`});
  const users=[...new Set(db.buys.filter(b=>b.listingId===l.id&&b.status==='pending'&&Date.now()-b.created<30*60*1000).map(b=>b.userId))];
  let message='Buy request sent! The seller will message you in chat with meetup details. No refunds.';
  if(users.length>1){
    if(games[l.id])message+=' A rock-paper-scissors game is already running for this card; you are queued.';
    else{const on=users.filter(isOnline);
      if(on.length>1){startRPS(l,on);message='Another buyer requested this card within 30 minutes: rock paper scissors!'}
      else message+=' Others also requested it, but they are offline, so first request wins.'}
  }
  res.json({message});
});
const BEATS={rock:'scissors',paper:'rock',scissors:'paper'};
function startRPS(l,players){
  const g={id:id(),listingId:l.id,title:l.title,players:[...players],alive:[...players],picks:{},round:1};games[l.id]=g;
  const names=players.map(p=>userById(p).username);
  players.forEach(p=>io.to('u:'+p).emit('rps:start',{gameId:g.id,listing:l.title,players:names}));
  g.timer=setTimeout(()=>resolveRPS(g),20000);
}
function resolveRPS(g){
  clearTimeout(g.timer);
  const pickers=g.alive.filter(u=>g.picks[u]);
  let alive=pickers.length?pickers:g.alive;
  const kinds=[...new Set(alive.map(u=>g.picks[u]).filter(Boolean))];
  if(pickers.length&&kinds.length===2){const [a,b]=kinds,w=BEATS[a]===b?a:b;alive=alive.filter(u=>g.picks[u]===w)}
  const reveal=Object.fromEntries(g.alive.map(u=>[userById(u)?.username,g.picks[u]||'(no pick)']));
  if(g.round>=6&&alive.length>1)alive=[alive[0]];
  if(alive.length===1)return finishRPS(g,alive[0],reveal);
  g.alive=alive;g.picks={};g.round++;
  g.players.forEach(p=>io.to('u:'+p).emit('rps:round',{reveal,alive:alive.map(u=>userById(u)?.username),canPlay:alive.includes(p)}));
  g.timer=setTimeout(()=>resolveRPS(g),20000);
}
function finishRPS(g,wid,reveal){
  const w=userById(wid);delete games[g.listingId];
  for(const b of db.buys)if(b.listingId===g.listingId&&b.status==='pending'&&g.players.includes(b.userId))b.status=b.userId===wid?'won':'lost';
  save();
  g.players.forEach(p=>io.to('u:'+p).emit('rps:end',{winner:w?.username,you:p===wid,reveal}));
  toAdmins('notify',{to:'sells',text:`@${w?.username} won rock-paper-scissors for "${g.title}"`});
}

// ---------- chat ----------
const inv=c=>({convoId:c.id,from:userById(c.a)?.username,topic:c.topic});
app.get('/api/convos',auth,(req,res)=>{const me=req.user.id;
  res.json(db.convos.filter(c=>c.a===me||c.b===me).map(c=>({id:c.id,other:userById(c.a===me?c.b:c.a)?.username,status:c.status,incoming:c.b===me,topic:c.topic})))});
app.get('/api/convos/:id/messages',auth,(req,res)=>{
  const c=db.convos.find(c=>c.id===req.params.id&&(c.a===req.user.id||c.b===req.user.id));
  if(!c)return bad(res,'Not found',404);res.json(db.messages.filter(m=>m.convoId===c.id).slice(-200));
});
io.use((s,next)=>{try{const u=userById(jwt.verify(cookieLib.parse(s.handshake.headers.cookie||'').tk,JWT_SECRET).id);if(!u)throw 0;s.user=u;next()}catch{next(new Error('auth'))}});
io.on('connection',s=>{
  const me=s.user;s.join('u:'+me.id);
  db.convos.filter(c=>c.b===me.id&&c.status==='pending').forEach(c=>s.emit('chat:invite',inv(c)));
  s.on('chat:request',({to,topic},ack)=>{
    const o=byName(to);if(!o||o.id===me.id)return ack?.({error:'User not found'});
    let c=db.convos.find(c=>(c.a===me.id&&c.b===o.id)||(c.a===o.id&&c.b===me.id));
    if(c&&c.status==='accepted')return ack?.({note:'You already have a chat open with @'+o.username});
    if(c&&c.status==='pending')return ack?.({error:'A request is already pending'});
    topic=String(topic||'Chat').slice(0,80);
    if(c){Object.assign(c,{a:me.id,b:o.id,status:'pending',topic})}else{c={id:id(),a:me.id,b:o.id,status:'pending',topic,created:Date.now()};db.convos.push(c)}
    save();io.to('u:'+o.id).emit('chat:invite',inv(c));ack?.({note:'Chat request sent to @'+o.username});
  });
  s.on('chat:respond',({convoId,accept})=>{
    const c=db.convos.find(c=>c.id===convoId&&c.b===me.id&&c.status==='pending');if(!c)return;
    c.status=accept?'accepted':'declined';save();
    [c.a,c.b].forEach(u=>io.to('u:'+u).emit(accept?'chat:accepted':'chat:declined',{convoId:c.id,by:me.username}));
  });
  s.on('chat:msg',({convoId,text})=>{
    const c=db.convos.find(c=>c.id===convoId&&c.status==='accepted'&&(c.a===me.id||c.b===me.id));
    text=String(text||'').trim().slice(0,1000);if(!c||!text)return;
    const m={id:id(),convoId,from:me.id,fromName:me.username,text,t:Date.now()};db.messages.push(m);save();
    [c.a,c.b].forEach(u=>io.to('u:'+u).emit('chat:msg',m));
  });
  s.on('rps:pick',({gameId,choice})=>{
    const g=Object.values(games).find(g=>g.id===gameId);
    if(!g||!g.alive.includes(me.id)||!BEATS[choice]||g.picks[me.id])return;
    g.picks[me.id]=choice;if(g.alive.every(u=>g.picks[u]))resolveRPS(g);
  });
});

loadDb().then(()=>server.listen(PORT,()=>console.log('CardVault running on :'+PORT))).catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});
