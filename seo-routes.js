/**
 * NoteNinja SEO routes: server-rendered pages for Google + students.
 * These are not spam pages; each page gives useful exam-focused content.
 */
'use strict';
const { SITE, buildPage, breadcrumb, faqSchema, articleSchema } = require('./seo-helpers');

function topicLink(topic) { return `/?topic=${encodeURIComponent(topic)}`; }
function pills(items){ return `<div class="pillbox">${items.map(([label,href])=>`<a class="pill" href="${href}">${label}</a>`).join('')}</div>`; }
function faqsHtml(faqs){ return faqs.map(f=>`<div class="faq"><b>${f.q}</b><p>${f.a}</p></div>`).join(''); }
function mcqHtml(mcqs){ return mcqs.map((m,i)=>`<div class="mcq"><b>Q${i+1}. ${m.q}</b><ul>${m.options.map((o,idx)=>`<li class="${idx===m.answer?'ok':''}">${o}</li>`).join('')}</ul></div>`).join(''); }
function cta(topic=''){ return `<div class="cta"><h2 style="border:0;margin-top:0">Make notes for your next exam topic</h2><p>Type any topic and NoteNinja will generate short notes, MCQs, flashcards and Q&A in seconds.</p><a href="/${topic ? '?topic='+encodeURIComponent(topic) : ''}">Generate AI Notes →</a><div class="small">Free for Indian students · Works for JEE, NEET, B.Tech and Boards</div></div>`; }

const pageList = [
  '/', '/about', '/faq', '/privacy-policy', '/terms',
  '/jee', '/neet', '/btech', '/topics/newtons-laws', '/topics/dbms-normalization'
];

function jeePage(){
  const bc = breadcrumb([{name:'Home',url:'/'},{name:'JEE Notes',url:'/jee'}]);
  const faqs = [
    {q:'Can I use NoteNinja for JEE revision?', a:'Yes. Use it for quick concept revision, short notes, MCQs and flashcards. For final accuracy, also verify important formulas from NCERT or coaching material.'},
    {q:'Which JEE topics should I revise first?', a:'Start with high-frequency topics: Mechanics, Current Electricity, Modern Physics, Chemical Bonding, Thermodynamics, GOC, Calculus, Coordinate Geometry and Probability.'},
    {q:'Is this enough for JEE Advanced?', a:'No single notes tool is enough for Advanced. Use NoteNinja for fast revision and recall, then solve previous year questions and advanced-level problems.'}
  ];
  const body = `<main class="wrap">${bc.html}<h1>JEE <em>Notes & AI Study Material</em></h1><p class="sub">Free short notes, MCQs and flashcards for JEE Main and Advanced preparation. Built for fast revision when you do not have time to read long chapters.</p>
  <h2>Best way to use this page</h2><p>Pick a topic, generate AI notes, then immediately test yourself using MCQs and flashcards. Do not only read notes. JEE rewards problem solving, so use notes as the starting point and questions as the real practice.</p>
  <h2>High-priority JEE topics</h2><div class="grid"><div class="card"><strong>Physics</strong><p>Newton's Laws, Work-Energy, Rotation, Current Electricity, Electrostatics, Optics, Modern Physics.</p></div><div class="card"><strong>Chemistry</strong><p>Mole Concept, Thermodynamics, Equilibrium, Chemical Bonding, GOC, Hydrocarbons, Coordination Compounds.</p></div><div class="card"><strong>Maths</strong><p>Limits, Derivatives, Integration, Matrices, Complex Numbers, Conics, Probability, Vectors.</p></div></div>
  <h2>Open topic notes</h2>${pills([["Newton's Laws",'/topics/newtons-laws'],['Ohm\'s Law',topicLink("Ohm's Law")],['Kinematics',topicLink('Kinematics')],['Chemical Bonding',topicLink('Chemical Bonding')],['Integration',topicLink('Integration')]])}
  <h2>Common mistake</h2><p class="note">Many students collect notes but do not revise actively. After generating notes, convert the same topic into MCQs and flashcards on NoteNinja. This gives better recall than passive reading.</p>
  <h2>FAQs</h2>${faqsHtml(faqs)}${cta('Newton Laws')}</main>`;
  return buildPage({title:'JEE Notes — Free AI Study Material, MCQs & Flashcards | NoteNinja', description:'Free JEE notes, MCQs and flashcards for Physics, Chemistry and Maths. Generate short AI notes for any JEE topic in seconds.', canonical:'/jee', activePath:'/jee', body, schemas:[articleSchema({headline:'JEE Notes and AI Study Material', description:'Free AI-powered JEE revision page for Physics, Chemistry and Maths.', url:'/jee'}), faqSchema(faqs), bc.schema]});
}

function neetPage(){
  const bc = breadcrumb([{name:'Home',url:'/'},{name:'NEET Notes',url:'/neet'}]);
  const faqs = [
    {q:'Is NCERT important for NEET Biology?', a:'Yes. NEET Biology is heavily NCERT-focused. Use NoteNinja for short revision, but always revise NCERT diagrams, tables and examples.'},
    {q:'Which NEET subject should I revise daily?', a:'Biology should be revised daily because it has the highest marks weightage, but Physics and Chemistry must also be practiced through MCQs.'},
    {q:'Can AI notes help in NEET?', a:'AI notes are useful for fast revision, summary and self-testing. They should support NCERT and previous year question practice, not replace them.'}
  ];
  const body = `<main class="wrap">${bc.html}<h1>NEET <em>Notes & Revision Material</em></h1><p class="sub">Generate short notes, MCQs and flashcards for NEET Biology, Physics and Chemistry topics.</p>
  <h2>NEET study focus</h2><div class="grid"><div class="card"><strong>Biology</strong><p>Genetics, Human Physiology, Plant Physiology, Ecology, Reproduction, Cell Biology.</p></div><div class="card"><strong>Physics</strong><p>Mechanics, Current Electricity, Modern Physics, Optics, Thermodynamics and Waves.</p></div><div class="card"><strong>Chemistry</strong><p>Chemical Bonding, Coordination Compounds, Equilibrium, Biomolecules, Organic basics.</p></div></div>
  <h2>Quick topic practice</h2>${pills([['DNA Replication',topicLink('DNA Replication')],['Photosynthesis',topicLink('Photosynthesis')],["Newton's Laws",'/topics/newtons-laws'],['Chemical Bonding',topicLink('Chemical Bonding')],['Human Heart',topicLink('Human Heart')]])}
  <h2>How to revise with NoteNinja</h2><ol><li>Generate short notes for one NCERT topic.</li><li>Read only the key points and formulas.</li><li>Attempt the generated MCQs without seeing answers first.</li><li>Save weak points as flashcards and revise next day.</li></ol>
  <h2>FAQs</h2>${faqsHtml(faqs)}${cta('DNA Replication')}</main>`;
  return buildPage({title:'NEET Notes — Free Biology, Physics & Chemistry AI Revision | NoteNinja', description:'Free NEET notes, MCQs and flashcards for Biology, Physics and Chemistry. Generate AI notes for any NEET topic instantly.', canonical:'/neet', activePath:'/neet', body, schemas:[articleSchema({headline:'NEET Notes and AI Revision Material', description:'Free AI-powered NEET revision page for Biology, Physics and Chemistry.', url:'/neet'}), faqSchema(faqs), bc.schema]});
}

function btechPage(){
  const bc = breadcrumb([{name:'Home',url:'/'},{name:'B.Tech Notes',url:'/btech'}]);
  const faqs = [
    {q:'Can B.Tech students use NoteNinja for semester exams?', a:'Yes. It is useful for quick theory revision, definitions, short answers, viva prep, MCQs and flashcards.'},
    {q:'Which subjects are best for NoteNinja?', a:'DBMS, DSA, Operating Systems, Computer Networks, Software Engineering and first-year engineering theory subjects work especially well.'},
    {q:'Can it help with placements?', a:'Yes. Use it to revise DSA, DBMS, OS, CN and OOP concepts before aptitude rounds and technical interviews.'}
  ];
  const body = `<main class="wrap">${bc.html}<h1>B.Tech <em>Notes for Semester Exams</em></h1><p class="sub">Short AI notes, MCQs and flashcards for engineering subjects like DBMS, DSA, OS, CN and Software Engineering.</p>
  <h2>Most useful B.Tech subjects</h2><div class="grid"><div class="card"><strong>DBMS</strong><p>ER model, SQL, keys, normalization, transactions, indexing and concurrency control.</p></div><div class="card"><strong>DSA</strong><p>Arrays, stack, queue, linked list, trees, graphs, sorting and complexity analysis.</p></div><div class="card"><strong>Operating System</strong><p>Processes, scheduling, deadlock, memory management, paging and file systems.</p></div><div class="card"><strong>Computer Networks</strong><p>OSI model, TCP/IP, routing, DNS, HTTP, congestion and error control.</p></div></div>
  <h2>Start here</h2>${pills([['DBMS Normalization','/topics/dbms-normalization'],['Stack in DSA',topicLink('Data Structures Stack')],['Process Scheduling',topicLink('OS Process Scheduling')],['Computer Networks',topicLink('Computer Networks')],['Software Engineering',topicLink('Software Engineering')]])}
  <h2>Exam strategy</h2><p>For theory subjects, first learn definitions, then diagrams, then differences, then short examples. NoteNinja is useful because it can convert one topic into all four formats quickly.</p>
  <h2>FAQs</h2>${faqsHtml(faqs)}${cta('DBMS Normalization')}</main>`;
  return buildPage({title:'B.Tech Notes — Free AI Notes for DBMS, DSA, OS & CN | NoteNinja', description:'Free B.Tech notes, MCQs and flashcards for DBMS, DSA, Operating Systems, Computer Networks and engineering semester exams.', canonical:'/btech', activePath:'/btech', body, schemas:[articleSchema({headline:'B.Tech Notes for Semester Exams', description:'Free AI-powered B.Tech notes for engineering students.', url:'/btech'}), faqSchema(faqs), bc.schema]});
}

function newtonsPage(){
  const bc = breadcrumb([{name:'Home',url:'/'},{name:'JEE Notes',url:'/jee'},{name:"Newton's Laws",url:'/topics/newtons-laws'}]);
  const faqs = [
    {q:"What are Newton's three laws?", a:'First law: an object stays at rest or uniform motion unless acted on by net force. Second law: F = ma. Third law: every action has equal and opposite reaction.'},
    {q:"Why is Newton's Laws important for JEE and NEET?", a:'It is the base of Mechanics. Questions on friction, circular motion, pulleys, blocks and connected bodies depend on Newton’s laws.'},
    {q:'What is the most common mistake?', a:'Students draw incomplete free-body diagrams. Always mark weight, normal reaction, tension, friction and applied force before solving.'}
  ];
  const mcqs = [
    {q:'A body remains at rest unless acted upon by external net force. This is:', options:['First law','Second law','Third law','Law of gravitation'], answer:0},
    {q:'SI unit of force is:', options:['Joule','Newton','Watt','Pascal'], answer:1},
    {q:'If mass is 2 kg and acceleration is 3 m/s², force is:', options:['5 N','6 N','1.5 N','9 N'], answer:1},
    {q:'Action and reaction forces act on:', options:['Same body','Different bodies','Only moving bodies','Only at rest'], answer:1},
    {q:'Friction acts:', options:['Along normal','Opposite relative motion tendency','Always forward','Only in air'], answer:1}
  ];
  const body = `<main class="wrap">${bc.html}<h1>Newton's Laws <em>Short Notes</em></h1><p class="sub">Exam-focused notes for JEE, NEET and Class 11 Physics with formulas, mistakes and MCQs.</p>
  <h2>Core idea</h2><p>Newton's Laws explain the relation between force, mass and motion. Most mechanics problems become simple when you draw a correct free-body diagram and apply net force equation along each axis.</p>
  <h2>Three laws</h2><ul><li><strong>First Law:</strong> A body continues in rest or uniform motion unless net external force acts on it.</li><li><strong>Second Law:</strong> Net force equals mass times acceleration: <strong>F = ma</strong>.</li><li><strong>Third Law:</strong> Every action has an equal and opposite reaction, acting on a different body.</li></ul>
  <h2>Common mistakes</h2><ul><li>Forgetting normal force.</li><li>Mixing action-reaction pair with balanced forces.</li><li>Taking friction direction without checking motion tendency.</li><li>Using F = ma before resolving forces into components.</li></ul>
  <h2>Practice MCQs</h2>${mcqHtml(mcqs)}<h2>FAQs</h2>${faqsHtml(faqs)}${cta("Newton's Laws")}</main>`;
  return buildPage({title:"Newton's Laws Notes for JEE, NEET & Class 11 | NoteNinja", description:"Newton's Laws short notes with formulas, free-body diagram tips, common mistakes and MCQs for JEE, NEET and Class 11 Physics.", canonical:'/topics/newtons-laws', activePath:'/topics/newtons-laws', body, schemas:[articleSchema({headline:"Newton's Laws Short Notes", description:"Exam-focused Newton's Laws notes with MCQs and common mistakes.", url:'/topics/newtons-laws'}), faqSchema(faqs), bc.schema]});
}

function dbmsPage(){
  const bc = breadcrumb([{name:'Home',url:'/'},{name:'B.Tech Notes',url:'/btech'},{name:'DBMS Normalization',url:'/topics/dbms-normalization'}]);
  const faqs = [
    {q:'What is normalization in DBMS?', a:'Normalization is the process of organizing database tables to reduce redundancy and avoid update, insert and delete anomalies.'},
    {q:'Which normal forms are most important for exams?', a:'1NF, 2NF, 3NF and BCNF are most important for B.Tech semester exams, viva and interviews.'},
    {q:'What is the difference between 3NF and BCNF?', a:'BCNF is stricter than 3NF. In BCNF, every determinant must be a candidate key.'}
  ];
  const mcqs = [
    {q:'1NF mainly removes:', options:['Partial dependency','Multivalued attributes','Transitive dependency','Candidate keys'], answer:1},
    {q:'2NF removes:', options:['Partial dependency','All keys','Tables','SQL queries'], answer:0},
    {q:'3NF removes:', options:['Atomic values','Transitive dependency','Primary key','Foreign key'], answer:1},
    {q:'BCNF requires every determinant to be:', options:['Foreign key','Candidate key','Composite attribute','Null'], answer:1},
    {q:'Normalization reduces:', options:['Redundancy','Security','Data integrity','Table names'], answer:0}
  ];
  const body = `<main class="wrap">${bc.html}<h1>DBMS Normalization <em>Short Notes</em></h1><p class="sub">Simple B.Tech notes for 1NF, 2NF, 3NF and BCNF with examples and MCQs.</p>
  <h2>Definition</h2><p>Normalization is a database design technique used to divide large tables into smaller related tables. The goal is to reduce duplicate data and prevent anomalies during insert, update and delete operations.</p>
  <h2>Normal forms</h2><ul><li><strong>1NF:</strong> Each cell should contain atomic/single values.</li><li><strong>2NF:</strong> Table should be in 1NF and have no partial dependency.</li><li><strong>3NF:</strong> Table should be in 2NF and have no transitive dependency.</li><li><strong>BCNF:</strong> For every functional dependency X → Y, X must be a candidate key.</li></ul>
  <h2>Exam tip</h2><p class="note">In answers, always mention dependency type, anomaly removed and one small example. This makes normalization answers much stronger in semester exams.</p>
  <h2>Practice MCQs</h2>${mcqHtml(mcqs)}<h2>FAQs</h2>${faqsHtml(faqs)}${cta('DBMS Normalization')}</main>`;
  return buildPage({title:'DBMS Normalization Notes — 1NF, 2NF, 3NF, BCNF | NoteNinja', description:'DBMS Normalization short notes for B.Tech: 1NF, 2NF, 3NF, BCNF, anomalies, dependencies and MCQs.', canonical:'/topics/dbms-normalization', activePath:'/topics/dbms-normalization', body, schemas:[articleSchema({headline:'DBMS Normalization Short Notes', description:'Exam-focused DBMS normalization notes for B.Tech students.', url:'/topics/dbms-normalization'}), faqSchema(faqs), bc.schema]});
}

function sitemap(req, res){
  const today = new Date().toISOString().split('T')[0];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${pageList.map(url=>`  <url><loc>${SITE}${url}</loc><lastmod>${today}</lastmod><changefreq>${url==='/'?'weekly':'monthly'}</changefreq><priority>${url==='/'?'1.0':url.startsWith('/topics')?'0.8':'0.9'}</priority></url>`).join('\n')}\n</urlset>`;
  res.setHeader('Content-Type','application/xml; charset=utf-8');
  res.status(200).send(xml);
}

function registerSeoRoutes(app){
  app.get('/jee', (req,res)=>res.type('html').send(jeePage()));
  app.get('/neet', (req,res)=>res.type('html').send(neetPage()));
  app.get('/btech', (req,res)=>res.type('html').send(btechPage()));
  app.get('/topics/newtons-laws', (req,res)=>res.type('html').send(newtonsPage()));
  app.get('/topics/dbms-normalization', (req,res)=>res.type('html').send(dbmsPage()));
  app.get('/sitemap.xml', sitemap);
}

module.exports = { registerSeoRoutes };
