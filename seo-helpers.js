/**
 * NoteNinja SEO helpers: reusable server-rendered page shell + schemas.
 */
'use strict';

const SITE = 'https://noteninja.online';
const YEAR = new Date().getFullYear();

function esc(s = '') {
  return String(s).replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function abs(url = '/') {
  return url.startsWith('http') ? url : SITE + (url.startsWith('/') ? url : '/' + url);
}

const css = `
:root{--bg:#080808;--surface:#111;--surface2:#181818;--border:#252525;--text:#f0f0f0;--muted:#909090;--red:#e63329;--green:#00d4aa;}
*{box-sizing:border-box;margin:0;padding:0} body{background:var(--bg);color:var(--text);font-family:'DM Sans',system-ui,sans-serif;line-height:1.75} a{color:var(--red);text-decoration:none} a:hover{text-decoration:underline}
nav{position:sticky;top:0;background:rgba(8,8,8,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);padding:0 22px;display:flex;gap:18px;align-items:center;flex-wrap:wrap;z-index:10}.logo{font-family:'DM Mono',monospace;color:var(--red);font-weight:700;padding:15px 0}.nav-link{font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);padding:15px 0}.nav-link[aria-current="page"]{color:var(--text)}
.wrap{max-width:850px;margin:0 auto;padding:48px 20px 92px}.crumb{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);margin-bottom:28px}.crumb a{color:var(--muted)} h1{font-family:'Syne',system-ui,sans-serif;font-size:clamp(29px,5vw,46px);line-height:1.08;margin-bottom:14px} h1 em{font-style:normal;color:var(--red)} .sub{color:var(--muted);max-width:650px;margin-bottom:34px} h2{font-family:'DM Mono',monospace;font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--red);border-bottom:1px solid var(--border);padding-bottom:8px;margin:38px 0 16px} h3{font-size:18px;margin:22px 0 8px} p,li{font-size:15px;color:#c9c9c9} p{margin-bottom:14px} ul,ol{padding-left:22px;margin-bottom:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:18px 0}.card,.mcq,.faq,.cta{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px}.card strong{display:block;color:var(--text);margin-bottom:6px}.pillbox{display:flex;flex-wrap:wrap;gap:9px;margin:14px 0}.pill{font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:7px 12px}.pill:hover{color:var(--text);border-color:var(--red);text-decoration:none}.mcq{margin-bottom:12px}.mcq b{color:var(--text)}.mcq ul{list-style:none;padding:0;margin:10px 0 0}.mcq li{border:1px solid var(--border);border-radius:8px;margin:7px 0;padding:8px 10px}.mcq .ok{border-color:#245b2a;color:#87d58d;background:#0d1d0f}.faq{margin-bottom:12px}.faq b{color:var(--text)}.cta{text-align:center;margin-top:42px;background:linear-gradient(180deg,#141414,#0d0d0d)}.cta a{display:inline-block;background:var(--red);color:#fff;border-radius:10px;padding:12px 22px;font-family:'DM Mono',monospace;margin-top:8px}.small{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);margin-top:12px} footer{border-top:1px solid #151515;text-align:center;padding:28px 16px 44px;font-family:'DM Mono',monospace;font-size:11px;color:rgba(255,255,255,.22)}footer a{color:rgba(255,255,255,.35);margin:0 8px}.note{border-left:3px solid var(--red);padding:12px 16px;background:#111;margin:18px 0;color:#cfcfcf}@media(max-width:640px){.wrap{padding:34px 16px 72px}nav{padding:0 15px;gap:12px}.grid{grid-template-columns:1fr}}
`;

function nav(active) {
  const links = [['/','Home'],['/jee','JEE'],['/neet','NEET'],['/btech','B.Tech'],['/topics/newtons-laws','Newton'],['/topics/dbms-normalization','DBMS'],['/about','About'],['/faq','FAQ']];
  return `<nav><a class="logo" href="/">🥷 NOTENINJA</a>${links.map(([href,label]) => `<a class="nav-link" href="${href}"${href===active?' aria-current="page"':''}>${label}</a>`).join('')}</nav>`;
}

function breadcrumb(items) {
  const html = `<div class="crumb">${items.map((it,i)=> i === items.length-1 ? esc(it.name) : `<a href="${it.url}">${esc(it.name)}</a> / `).join('')}</div>`;
  const schema = { '@context':'https://schema.org', '@type':'BreadcrumbList', itemListElement: items.map((it,i)=>({ '@type':'ListItem', position:i+1, name:it.name, item:abs(it.url)})) };
  return { html, schema };
}

function faqSchema(faqs) { return { '@context':'https://schema.org', '@type':'FAQPage', mainEntity: faqs.map(f=>({ '@type':'Question', name:f.q, acceptedAnswer:{ '@type':'Answer', text:f.a.replace(/<[^>]*>/g,'') }})) }; }
function articleSchema({headline, description, url}) { return { '@context':'https://schema.org', '@type':'Article', headline, description, url:abs(url), image: abs('/og-image.png'), author:{'@type':'Organization', name:'NoteNinja'}, publisher:{'@type':'EducationalOrganization', name:'NoteNinja', url:SITE}, dateModified: new Date().toISOString().split('T')[0], inLanguage:'en-IN' }; }
function webAppSchema(){ return {'@context':'https://schema.org','@type':'WebApplication',name:'NoteNinja',url:SITE,applicationCategory:'EducationalApplication',operatingSystem:'Web',description:'Free AI study tool for Indian students preparing for JEE, NEET, B.Tech and Board exams.',offers:{'@type':'Offer',price:'0',priceCurrency:'INR'},isAccessibleForFree:true}; }

function buildPage({title, description, canonical, activePath, body, schemas=[]}) {
  return `<!doctype html><html lang="en-IN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><meta name="description" content="${esc(description)}"><meta name="robots" content="index, follow"><link rel="canonical" href="${abs(canonical)}"><meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(description)}"><meta property="og:url" content="${abs(canonical)}"><meta property="og:type" content="article"><meta property="og:site_name" content="NoteNinja"><meta property="og:image" content="${SITE}/og-image.png"><meta name="twitter:card" content="summary_large_image"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"><style>${css}</style>${[webAppSchema(),...schemas].map(s=>`<script type="application/ld+json">${JSON.stringify(s)}</script>`).join('')}</head><body>${nav(activePath)}${body}<footer><div>🥷 NOTENINJA</div><div><a href="/jee">JEE</a><a href="/neet">NEET</a><a href="/btech">B.Tech</a><a href="/about">About</a><a href="/faq">FAQ</a><a href="/privacy-policy">Privacy</a><a href="/terms">Terms</a></div><div>© ${YEAR} NoteNinja · Study smarter, score higher.</div></footer></body></html>`;
}

module.exports = { SITE, esc, buildPage, breadcrumb, faqSchema, articleSchema };
