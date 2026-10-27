import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, mkdirSync } from 'node:fs';
import { resolve, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { installAdmin } from './lib/admin.js';

const root = dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DB_PATH || resolve(root, 'data/store.db');
mkdirSync(dirname(dbPath), { recursive: true });
const db = new DatabaseSync(dbPath);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT NOT NULL,category TEXT NOT NULL,price INTEGER NOT NULL,old_price INTEGER,image TEXT NOT NULL,description TEXT NOT NULL,tag TEXT);
CREATE TABLE IF NOT EXISTS variants(product_id INTEGER REFERENCES products(id),size TEXT,color TEXT,stock INTEGER NOT NULL CHECK(stock>=0),PRIMARY KEY(product_id,size,color));
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,postal TEXT NOT NULL,total INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(order_id TEXT REFERENCES orders(id),product_id INTEGER REFERENCES products(id),name TEXT,size TEXT,color TEXT,quantity INTEGER,price INTEGER);`);
const photos = ['photo-1475180098004-ca77a66827be','photo-1483985988355-763728e1935b','photo-1539109136881-3be0616acf4b','photo-1483985988355-763728e1935b','photo-1483985988355-763728e1935b','photo-1475180098004-ca77a66827be','photo-1539109136881-3be0616acf4b','photo-1475180098004-ca77a66827be'];
if (!db.prepare('SELECT id FROM products LIMIT 1').get()) {
 const records = [
 ['شلوار پارچه‌ای راسته آوا','pants',1280000,1490000,'انتخابی خوش‌دوخت برای استایل روزمره و رسمی. پارچه لطیف با ایستایی زیبا و فاق بلند.','پرفروش'],
 ['شومیز ساتن مهتاب','tops',980000,null,'شومیز ساتن لطیف با برش آزاد؛ همراهی ساده و شیک برای دورهمی‌ها.','جدید'],
 ['پیراهن مجلسی رها','dresses',2450000,2800000,'پیراهنی با برش مینیمال و فرم کلاسیک برای لحظه‌های خاص شما.','منتخب شفق'],
 ['کت زنانه آتریسا','outerwear',2180000,null,'کت خوش‌فرم با دوخت ظریف، مناسب ترکیب با شلوارهای پارچه‌ای.','جدید'],
 ['شلوار واید لینن دریا','pants',1190000,null,'شلوار واید با حس سبک و راحت، مناسب استایل‌های آرام و روزمره.',''],
 ['شلوار کلاسیک نوا','pants',1380000,null,'طراحی کلاسیک با خطوط ساده و کمر خوش‌فرم برای یک استایل ماندگار.',''],
 ['پیراهن بلند آناهیتا','dresses',2690000,null,'پیراهن بلند با فرم روان و جزئیات ظریف برای مهمانی‌های شما.','جدید'],
 ['شومیز کرپ ترنم','tops',890000,1050000,'شومیز ساده و کاربردی با پارچه کرپ و دوخت تمیز.','پیشنهاد ویژه']
 ];
 const insert = db.prepare('INSERT INTO products(id,name,category,price,old_price,image,description,tag) VALUES(?,?,?,?,?,?,?,?)');
 const variant = db.prepare('INSERT INTO variants VALUES(?,?,?,?)');
 records.forEach((p,i)=>{ insert.run(i+1,p[0],p[1],p[2],p[3],`https://images.unsplash.com/${photos[i]}?auto=format&fit=crop&w=900&q=85`,p[4],p[5]); for(const size of ['۳۶','۳۸','۴۰','۴۲','۴۴']) for(const color of ['مشکی','کرم','زرشکی']) variant.run(i+1,size,color,5); });
}
const json = (res,code,data)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
const normalizeDigits = s => String(s||'').replace(/[۰-۹]/g,c=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(c)).replace(/[٠-٩]/g,c=>'٠١٢٣٤٥٦٧٨٩'.indexOf(c));
async function body(req){let text='';for await(const chunk of req){text+=chunk;if(Buffer.byteLength(text)>32768)throw Error('اطلاعات ارسالی بیش از حد مجاز است.');}try{return JSON.parse(text);}catch{throw Error('اطلاعات ارسالی معتبر نیست.');}}
// کد اصلاح‌شده
const adminHandler = installAdmin(db, { json, body });
if (process.env.NODE_ENV === 'production' && (!process.env.APP_ORIGIN || new URL(process.env.APP_ORIGIN).protocol !== 'https:')) throw Error('Production requires APP_ORIGIN=https://your-domain');
const server = http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');
 try{
 const url = new URL(req.url,'http://localhost');
 const allowedHosts=process.env.APP_ORIGIN?[new URL(process.env.APP_ORIGIN).host]:[`localhost:${process.env.PORT||3000}`,`127.0.0.1:${process.env.PORT||3000}`];
 if(!allowedHosts.includes(req.headers.host)) return json(res,403,{error:'Host is not allowed.'});
 res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
 res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
 if(process.env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000');
 if(url.pathname.startsWith('/admin'))res.setHeader('Cache-Control','no-store');
 if(await adminHandler(req,res,url))return;
 if(url.pathname==='/api/products' && req.method==='GET'){const products=db.prepare('SELECT * FROM products WHERE active=1 AND deleted_at IS NULL').all().map(p=>({...p,variants:db.prepare('SELECT size,color,stock FROM variants WHERE product_id=?').all(p.id)}));return json(res,200,products);}
 if(url.pathname==='/api/orders' && req.method==='POST'){
 const origin=req.headers.origin;if(origin && new URL(origin).host!==req.headers.host)return json(res,403,{error:'درخواست مجاز نیست.'});
 const data=await body(req);const name=String(data.name||'').trim(),phone=normalizeDigits(data.phone),address=String(data.address||'').trim(),postal=normalizeDigits(data.postal);
 if(name.length<3||name.length>100||!/^09\d{9}$/.test(phone)||address.length<10||address.length>1000||!/^\d{10}$/.test(postal))return json(res,400,{error:'نام، موبایل، آدرس کامل و کد پستی ۱۰ رقمی را درست وارد کنید.'});
 if(!Array.isArray(data.items)||data.items.length===0||data.items.length>30)return json(res,400,{error:'سبد خرید معتبر نیست.'});
 const id='SH-'+randomBytes(6).toString('hex').toUpperCase();
 db.exec('BEGIN IMMEDIATE');
 try{
 let subtotal=0;const items=[];
 for(const item of data.items){if(!Number.isInteger(item.quantity)||item.quantity<1||item.quantity>10)throw Error('تعداد محصول معتبر نیست.');
 const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1 AND deleted_at IS NULL').get(Number(item.id));if(!p)throw Error('محصول پیدا نشد.');
 const result=db.prepare('UPDATE variants SET stock=stock-? WHERE product_id=? AND size=? AND color=? AND stock>=?').run(item.quantity,p.id,String(item.size),String(item.color),item.quantity);
 if(!result.changes)throw Error(`موجودی ${p.name} برای انتخاب شما کافی نیست.`);
 db.prepare('UPDATE products SET version=version+1 WHERE id=?').run(p.id);
 subtotal+=p.price*item.quantity;items.push({...item,name:p.name,price:p.price});}
 const shipping=subtotal>=2500000?0:85000;const total=subtotal+shipping;
 db.prepare('INSERT INTO orders(id,name,phone,address,postal,total) VALUES(?,?,?,?,?,?)').run(id,name,phone,address,postal,total);
 const stmt=db.prepare('INSERT INTO order_items VALUES(?,?,?,?,?,?,?)');for(const item of items)stmt.run(id,item.id,item.name,item.size,item.color,item.quantity,item.price);
 db.exec('COMMIT');return json(res,201,{id,total,shipping,status:'pending'});
 }catch(e){db.exec('ROLLBACK');return json(res,400,{error:e.message});}
 }
 if(url.pathname.startsWith('/api/'))return json(res,404,{error:'مسیر پیدا نشد.'});
 if(!['GET','HEAD'].includes(req.method))return json(res,405,{error:'متد مجاز نیست.'});
 const paths={'/':'index.html','/admin':'admin.html','/styles.css':'styles.css','/app.js':'app.js','/admin.js':'admin.js','/admin.css':'admin.css'};const file=paths[url.pathname];if(!file)return json(res,404,{error:'صفحه پیدا نشد.'});
 const content=readFileSync(resolve(root,'public',file));res.writeHead(200,{'Content-Type':({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'})[extname(file)]});res.end(req.method==='HEAD'?undefined:content);
 }catch(e){console.error('Request failed:',e.code||'INVALID_REQUEST');json(res,400,{error:'درخواست انجام نشد. دوباره تلاش کنید.'});}
});
server.listen(Number(process.env.PORT||3000),'127.0.0.1',()=>console.log(`Shafagh: http://localhost:${process.env.PORT||3000}`));
