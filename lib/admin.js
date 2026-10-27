import { authSchema, passwordHash, equal, digest, token } from './security.js';

export function installAdmin(db, { json, body }) {
  authSchema(db);
  const columns = new Set(db.prepare('PRAGMA table_info(products)').all().map(c => c.name));
  for (const [name, definition] of Object.entries({active:'INTEGER NOT NULL DEFAULT 1',deleted_at:'TEXT',version:'INTEGER NOT NULL DEFAULT 1'})) {
    if (!columns.has(name)) db.exec(`ALTER TABLE products ADD COLUMN ${name} ${definition}`);
  }
  if (!db.prepare('PRAGMA table_info(orders)').all().some(c => c.name === 'tracking')) db.exec("ALTER TABLE orders ADD COLUMN tracking TEXT NOT NULL DEFAULT ''");
  db.exec(`CREATE TABLE IF NOT EXISTS categories(slug TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE);
  CREATE TABLE IF NOT EXISTS admin_audit(id INTEGER PRIMARY KEY,username TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
  const labels = {pants:'شلوار زنانه',tops:'شومیز و بلوز',dresses:'لباس مجلسی',outerwear:'کت زنانه'};
  for (const row of db.prepare('SELECT DISTINCT category FROM products').all()) db.prepare('INSERT OR IGNORE INTO categories VALUES(?,?)').run(row.category, labels[row.category] || row.category);
  const fail = (message, status = 400) => { const e = Error(message); e.status = status; throw e; };
  const text = (v, label, min, max) => { if (typeof v !== 'string' || v.trim().length < min || v.trim().length > max) fail(`${label} باید بین ${min} و ${max} نویسه باشد.`); return v.trim(); };
  const integer = (v, label, min, max) => { if (!Number.isSafeInteger(v) || v < min || v > max) fail(`${label} معتبر نیست.`); return v; };
  const transact = fn => { db.exec('BEGIN IMMEDIATE'); try { const result = fn(); db.exec('COMMIT'); return result; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  const audit = (session, action, target) => db.prepare('INSERT INTO admin_audit(username,action,target) VALUES(?,?,?)').run(session.username, action, String(target));
  const productList = () => db.prepare('SELECT * FROM products ORDER BY id DESC').all().map(p => ({...p, variants:db.prepare('SELECT size,color,stock FROM variants WHERE product_id=? ORDER BY size,color').all(p.id)}));
  const cookieName = process.env.NODE_ENV === 'production' ? '__Host-shafagh_admin' : 'shafagh_admin';
  const cookie = (value, age) => `${cookieName}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
  const sessionFor = req => {
    const value = (req.headers.cookie || '').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='))?.slice(cookieName.length+1);
    if (!value || !/^[a-f0-9]{64}$/.test(value)) return null;
    const row = db.prepare('SELECT * FROM admin_sessions WHERE token_hash=?').get(digest(value));
    if (!row) return null;
    if (row.expires < Date.now() || row.last_seen < Date.now() - 30*60*1000) { db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(row.token_hash); return null; }
    db.prepare('UPDATE admin_sessions SET last_seen=? WHERE token_hash=?').run(Date.now(), row.token_hash);
    return row;
  };
  const validProduct = data => {
    if (!data || typeof data !== 'object') fail('اطلاعات محصول معتبر نیست.');
    const p = {name:text(data.name,'نام',2,150),category:text(data.category,'دسته‌بندی',1,60),description:text(data.description,'توضیحات',0,5000),tag:text(data.tag,'برچسب',0,40),image:text(data.image,'آدرس تصویر',1,2000),price:integer(data.price,'قیمت',1,1000000000),old_price:data.old_price === null ? null : integer(data.old_price,'قیمت قبلی',1,1000000000),active:data.active};
    if (typeof p.active !== 'boolean') fail('وضعیت انتشار معتبر نیست.');
    if (p.old_price !== null && p.old_price <= p.price) fail('قیمت قبلی باید بیشتر از قیمت فروش باشد.');
    if (!db.prepare('SELECT slug FROM categories WHERE slug=?').get(p.category)) fail('دسته‌بندی پیدا نشد.');
    let image; try { image = new URL(p.image); } catch { fail('آدرس تصویر معتبر نیست.'); }
    if (image.protocol !== 'https:' || image.username || image.password) fail('برای تصویر از آدرس HTTPS بدون اطلاعات ورود استفاده کنید.');
    p.image = image.href;
    if (!Array.isArray(data.variants) || data.variants.length < 1 || data.variants.length > 100) fail('بین ۱ تا ۱۰۰ ترکیب سایز و رنگ وارد کنید.');
    const keys = new Set();
    p.variants = data.variants.map(v=>{const size=text(v.size,'سایز',1,30),color=text(v.color,'رنگ',1,40),stock=integer(v.stock,'موجودی',0,100000);const key=JSON.stringify([size,color]);if(keys.has(key))fail('ترکیب سایز و رنگ تکراری است.');keys.add(key);return {size,color,stock};});
    return p;
  };
  let loginBusy = false;
  return async function handleAdmin(req, res, url) {
    if (url.pathname === '/api/categories' && req.method === 'GET') { json(res,200,db.prepare('SELECT * FROM categories ORDER BY rowid').all()); return true; }
    if (!url.pathname.startsWith('/api/admin/')) return false;
    try {
      const write = !['GET','HEAD'].includes(req.method);
      if (write) {
        const expected = process.env.APP_ORIGIN || `http://${req.headers.host}`;
        if (req.headers.origin !== expected || req.headers['sec-fetch-site'] === 'cross-site') fail('درخواست از مبدأ مجاز ارسال نشده است.',403);
        if (!req.headers['content-type']?.startsWith('application/json')) fail('نوع درخواست باید JSON باشد.',415);
      }
      if (url.pathname === '/api/admin/login' && req.method === 'POST') {
        const key=req.socket.remoteAddress || 'local', now=Date.now();
        db.prepare('DELETE FROM login_limits WHERE until_time<?').run(now);
        const limit=db.prepare('SELECT * FROM login_limits WHERE key=?').get(key);
        if (limit?.count >= 5) { res.setHeader('Retry-After',String(Math.ceil((limit.until_time-now)/1000))); fail('تلاش‌های ورود زیاد است؛ ۱۵ دقیقه بعد دوباره امتحان کنید.',429); }
        if (loginBusy) fail('ورود در حال بررسی است؛ کمی بعد تلاش کنید.',429);
        const data=await body(req);
        const credentials=db.prepare('SELECT * FROM admin_credentials WHERE id=1').get();
        if (!credentials) fail('مدیر هنوز ساخته نشده است. در ترمینال پروژه npm run admin:setup را اجرا کنید.',503);
        if (typeof data.password !== 'string' || data.password.length > 128 || typeof data.username !== 'string' || data.username.length>40) fail('اطلاعات ورود معتبر نیست.');
        db.prepare('INSERT INTO login_limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1').run(key,now+15*60*1000);
        loginBusy=true; let verified;
        try { const candidate=await passwordHash(data.password,credentials.salt);verified=equal(candidate.hash,credentials.hash)&&equal(data.username,credentials.username); } finally { loginBusy=false; }
        if (!verified) fail('نام کاربری یا رمز عبور نادرست است.',401);
        // A local password reset during verification must invalidate this attempt.
        if (!equal(db.prepare('SELECT hash FROM admin_credentials WHERE id=1').get()?.hash,credentials.hash)) fail('رمز تغییر کرده است؛ دوباره وارد شوید.',401);
        db.prepare('DELETE FROM login_limits WHERE key=?').run(key);
        db.prepare('DELETE FROM admin_sessions WHERE expires<? OR last_seen<?').run(now,now-30*60*1000);
        const previous=sessionFor(req);if(previous)db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(previous.token_hash);
        const value=token(),csrf=token();
        db.prepare('INSERT INTO admin_sessions VALUES(?,?,?,?,?)').run(digest(value),csrf,credentials.username,now+8*60*60*1000,now);
        res.setHeader('Set-Cookie',cookie(value,8*60*60));audit(credentials,'login','session');
        json(res,200,{username:credentials.username,csrf});return true;
      }
      const session=sessionFor(req);if(!session)fail('نشست ورود معتبر نیست. دوباره وارد شوید.',401);
      if(write && !equal(req.headers['x-csrf-token'],session.csrf))fail('توکن امنیتی معتبر نیست؛ صفحه را تازه کنید.',403);
      if(url.pathname==='/api/admin/session' && req.method==='GET'){json(res,200,{username:session.username,csrf:session.csrf});return true;}
      if(url.pathname==='/api/admin/logout' && req.method==='POST'){db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(session.token_hash);res.setHeader('Set-Cookie',cookie('',0));json(res,200,{ok:true});return true;}
      if(url.pathname==='/api/admin/products' && req.method==='GET'){json(res,200,productList());return true;}
      const productMatch=url.pathname.match(/^\/api\/admin\/products\/(\d+)$/);
      if((url.pathname==='/api/admin/products' && req.method==='POST') || (productMatch && req.method==='PUT')){
        const data=await body(req),p=validProduct(data),id=productMatch?Number(productMatch[1]):null;
        const saved=transact(()=>{
          let target=id;
          if(id){const old=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!old)fail('محصول پیدا نشد.',404);if(old.deleted_at)fail('ابتدا محصول را بازیابی کنید.',409);if(data.version!==old.version)fail('محصول یا موجودی تغییر کرده است؛ فهرست را تازه کنید و دوباره ویرایش کنید.',409);
            db.prepare('UPDATE products SET name=?,category=?,price=?,old_price=?,image=?,description=?,tag=?,active=?,version=version+1 WHERE id=?').run(p.name,p.category,p.price,p.old_price,p.image,p.description,p.tag,Number(p.active),id);
            db.prepare('DELETE FROM variants WHERE product_id=?').run(id);
          }else{target=Number(db.prepare('INSERT INTO products(name,category,price,old_price,image,description,tag,active) VALUES(?,?,?,?,?,?,?,?)').run(p.name,p.category,p.price,p.old_price,p.image,p.description,p.tag,Number(p.active)).lastInsertRowid);}
          for(const v of p.variants)db.prepare('INSERT INTO variants VALUES(?,?,?,?)').run(target,v.size,v.color,v.stock);
          audit(session,id?'product.update':'product.create',target);return target;
        });json(res,id?200:201,{id:saved});return true;
      }
      if(productMatch && ['DELETE','PATCH'].includes(req.method)){
        const data=await body(req),id=Number(productMatch[1]);
        transact(()=>{const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p)fail('محصول پیدا نشد.',404);if(data.version!==p.version)fail('محصول تغییر کرده است؛ صفحه را تازه کنید.',409);
          if(req.method==='DELETE'){db.prepare("UPDATE products SET deleted_at=CURRENT_TIMESTAMP,active=0,version=version+1 WHERE id=?").run(id);audit(session,'product.archive',id);}
          else{if(!p.deleted_at)fail('محصول حذف نشده است.',409);db.prepare('UPDATE products SET deleted_at=NULL,active=0,version=version+1 WHERE id=?').run(id);audit(session,'product.restore',id);}
        });json(res,200,{ok:true});return true;
      }
      if(url.pathname==='/api/admin/categories' && req.method==='GET'){json(res,200,db.prepare('SELECT c.*,COUNT(p.id) AS product_count FROM categories c LEFT JOIN products p ON p.category=c.slug GROUP BY c.slug ORDER BY c.rowid').all());return true;}
      const catMatch=url.pathname.match(/^\/api\/admin\/categories\/([a-z0-9-]+)$/);
      if((url.pathname==='/api/admin/categories' && req.method==='POST') || (catMatch && req.method==='PUT')){
        const data=await body(req),name=text(data.name,'نام دسته‌بندی',2,60),slug=catMatch?catMatch[1]:text(data.slug,'شناسه',1,60);
        if(!/^[a-z][a-z0-9-]{0,59}$/.test(slug)||slug==='all')fail('شناسه باید با حرف انگلیسی شروع شود و فقط حروف کوچک، عدد و خط تیره داشته باشد.');
        transact(()=>{if(catMatch){if(!db.prepare('SELECT slug FROM categories WHERE slug=?').get(slug))fail('دسته‌بندی پیدا نشد.',404);db.prepare('UPDATE categories SET name=? WHERE slug=?').run(name,slug);}else db.prepare('INSERT INTO categories VALUES(?,?)').run(slug,name);audit(session,catMatch?'category.update':'category.create',slug);});json(res,200,{ok:true});return true;
      }
      if(catMatch && req.method==='DELETE'){
        transact(()=>{if(db.prepare('SELECT id FROM products WHERE category=? LIMIT 1').get(catMatch[1]))fail('این دسته محصول دارد؛ ابتدا دسته محصولات (حتی حذف‌شده‌ها) را تغییر دهید.',409);if(!db.prepare('DELETE FROM categories WHERE slug=?').run(catMatch[1]).changes)fail('دسته‌بندی پیدا نشد.',404);audit(session,'category.delete',catMatch[1]);});json(res,200,{ok:true});return true;
      }
      if(url.pathname==='/api/admin/orders' && req.method==='GET'){json(res,200,db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all().map(o=>({...o,items:db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id)})));return true;}
      const orderMatch=url.pathname.match(/^\/api\/admin\/orders\/(SH-[A-F0-9]+)$/);
      if(orderMatch && req.method==='PATCH'){
        const data=await body(req),tracking=text(data.tracking??'','کد رهگیری',0,100);
        transact(()=>{const o=db.prepare('SELECT * FROM orders WHERE id=?').get(orderMatch[1]);if(!o)fail('سفارش پیدا نشد.',404);if(o.status!==data.previous_status)fail('سفارش تغییر کرده است؛ صفحه را تازه کنید.',409);
          const next={pending:['processing','cancelled'],processing:['shipped','cancelled'],shipped:['delivered'],delivered:[],cancelled:[]};
          if(data.status!==o.status && !next[o.status]?.includes(data.status))fail('تغییر وضعیت مجاز نیست.',409);
          if(['shipped','delivered'].includes(data.status)&&!tracking)fail('کد رهگیری ارسال لازم است.');
          if(data.status==='cancelled'&&o.status!=='cancelled')for(const i of db.prepare('SELECT * FROM order_items WHERE order_id=?').all(o.id)){
            db.prepare('INSERT INTO variants VALUES(?,?,?,?) ON CONFLICT(product_id,size,color) DO UPDATE SET stock=stock+excluded.stock').run(i.product_id,i.size,i.color,i.quantity);
            db.prepare('UPDATE products SET version=version+1 WHERE id=?').run(i.product_id);
          }
          db.prepare('UPDATE orders SET status=?,tracking=? WHERE id=?').run(data.status,tracking,o.id);audit(session,'order.'+data.status,o.id);
        });json(res,200,{ok:true});return true;
      }
      if(url.pathname==='/api/admin/audit' && req.method==='GET'){json(res,200,db.prepare('SELECT * FROM admin_audit ORDER BY id DESC LIMIT 100').all());return true;}
      fail('مسیر پیدا نشد.',404);
    }catch(e){json(res,e.status||400,{error:e.status?e.message:e.code?.includes('SQLITE')?'اطلاعات تکراری یا ناسازگار است. نام و شناسه را بررسی کنید.':'اطلاعات درخواست معتبر نیست.'});return true;}
  };
}
