"use strict";
/* Audit Workbench client. Talks to server.py's JSON API; no external libraries. */

/* ---------- Domain rules ---------- */
const LEVELS = ['Critical', 'High', 'Medium', 'Low'];
function riskScore(l, i){ return (Number(l) || 0) * (Number(i) || 0); }
function criticality(l, i){
  const s = riskScore(l, i);
  return s >= 20 ? 'Critical' : s >= 12 ? 'High' : s >= 6 ? 'Medium' : 'Low';
}
// Typical attribute-sampling sizes per control frequency: [non-key, key control].
const SAMPLE_GUIDE = {
  'Annual':[1,1], 'Quarterly':[2,2], 'Monthly':[2,5], 'Weekly':[5,15], 'Daily':[20,40],
  'Multiple times per day':[25,60], 'Automated':[1,1], 'As needed':[10,25]
};
const suggestedSample = (freq, key) => SAMPLE_GUIDE[freq] ? SAMPLE_GUIDE[freq][key ? 1 : 0] : '';
const CLOSED = ['Complete', 'Closed', 'Risk accepted', 'Completed', 'Cancelled'];
const today = () => new Date().toISOString().slice(0, 10);
const isOverdue = (date, status) => !!date && !CLOSED.includes(status) && date < today();
const AUDIT_CYCLE_MONTHS = {'Annual':12, 'Every 2 years':24, 'Every 3 years':36, 'Continuous':3};
function nextAuditDue(u){
  const m = AUDIT_CYCLE_MONTHS[u.frequency]; if (!u.last_audited || !m) return '';
  const d = new Date(u.last_audited + 'T00:00:00Z'); d.setUTCMonth(d.getUTCMonth() + m); return d.toISOString().slice(0, 10);
}

/* ---------- Schemas (keys match server columns) ---------- */
const FRAMEWORKS = ['SOX ITGC','ISO/IEC 27001:2022','NIST CSF 2.0','NIST SP 800-53','COBIT 2019','PCI DSS 4.0','SOC 2','Internal policy','Other'];
const L5 = [['1','1 - Rare'],['2','2 - Unlikely'],['3','3 - Possible'],['4','4 - Likely'],['5','5 - Almost certain']];
const I5 = [['1','1 - Minimal'],['2','2 - Minor'],['3','3 - Moderate'],['4','4 - Major'],['5','5 - Severe']];
const AREAS = ['Logical access','Privileged access','Change management','IT operations / job scheduling','Backup & recovery','Network security',
  'Vendor / third-party management','Data protection','Physical security','Incident management','Cloud security','Business continuity'];
const PURPOSES = ['Population (e.g. user extraction)','Sample selection','Testing performed / tick-marked results','Supporting documentation','Exception follow-up'];
const SCHEMAS = {
  universe:{label:'Auditable entity', fields:[
    {k:'name',l:'Entity (system, process or location)',req:1},{k:'category',l:'Category',t:'select',o:['Application','Infrastructure','Process','Vendor','Location','Project']},
    {k:'owner',l:'Business owner'},{k:'frequency',l:'Audit cycle',t:'select',o:Object.keys(AUDIT_CYCLE_MONTHS)},
    {k:'likelihood',l:'Risk likelihood',t:'select',o:L5},{k:'impact',l:'Risk impact',t:'select',o:I5},
    {k:'last_audited',l:'Last audited',t:'date'},{k:'description',l:'Description',t:'area',w:1},{k:'notes',l:'Notes',t:'area',w:1}]},
  plan:{label:'Plan item', fields:[
    {k:'title',l:'Audit title',req:1},{k:'universe_id',l:'Auditable entity',t:'ref',ref:'universe'},
    {k:'year',l:'Plan year',t:'number',req:1},{k:'quarter',l:'Quarter',t:'select',o:['Q1','Q2','Q3','Q4']},
    {k:'lead_id',l:'Audit lead',t:'user'},{k:'budget_hours',l:'Budget hours',t:'number'},
    {k:'status',l:'Status',t:'select',o:['Planned','In progress','Completed','Deferred','Cancelled']},{k:'notes',l:'Rationale / notes',t:'area',w:1}]},
  engagements:{label:'Engagement', fields:[
    {k:'name',l:'Engagement name',req:1},{k:'auditee',l:'Auditee / business unit'},
    {k:'universe_id',l:'Auditable entity',t:'ref',ref:'universe'},{k:'framework',l:'Primary framework',t:'select',o:FRAMEWORKS},
    {k:'status',l:'Phase',t:'select',o:['Planning','Fieldwork','Reporting','Follow-up','Closed']},
    {k:'lead_id',l:'Engagement lead',t:'user'},{k:'team',l:'Team members',hint:'Names, comma separated'},{k:'budget_hours',l:'Budget hours',t:'number'},
    {k:'period_start',l:'Audit period from',t:'date'},{k:'period_end',l:'Audit period to',t:'date'},
    {k:'field_start',l:'Fieldwork start',t:'date'},{k:'field_end',l:'Fieldwork end',t:'date'},
    {k:'objectives',l:'Objectives',t:'area',w:1},{k:'scope',l:'Scope (systems, locations, processes)',t:'area',w:1},
    {k:'out_of_scope',l:'Out of scope / limitations',t:'area',w:1}]},
  risks:{label:'Risk area', fields:[
    {k:'area',l:'Auditable area',req:1,list:AREAS},{k:'system',l:'In-scope systems'},{k:'description',l:'Risk description',t:'area',w:1},
    {k:'likelihood',l:'Inherent likelihood',t:'select',o:L5},{k:'impact',l:'Inherent impact',t:'select',o:I5},
    {k:'response',l:'Planned audit response',t:'area',w:1}]},
  workpapers:{label:'Workpaper', fields:[
    {k:'ref',l:'Workpaper ref / control ID',req:1},{k:'title',l:'Control name',req:1},
    {k:'risk_id',l:'Risk area',t:'ref',ref:'risks'},{k:'framework_ref',l:'Framework reference',hint:'e.g. ISO A.5.15, NIST AC-2'},
    {k:'control_desc',l:'Control description',t:'area',w:1},
    {k:'nature',l:'Control nature',t:'select',o:['Manual','IT-dependent manual','Automated']},
    {k:'frequency',l:'Control frequency',t:'select',o:Object.keys(SAMPLE_GUIDE)},{k:'key_control',l:'Key control?',t:'select',o:['Yes','No']},
    {k:'test_type',l:'Test method',t:'select',o:['Inquiry','Observation','Inspection','Re-performance','Walkthrough (design)']},
    {k:'procedure',l:'Test procedure / steps',t:'area',w:1},
    {k:'population',l:'Population (source & size)'},{k:'sample_size',l:'Sample size',hint:'Suggested from frequency; edit if needed'},
    {k:'exceptions',l:'Exceptions found',t:'number'},{k:'assigned_to',l:'Assigned to',t:'user'},{k:'due_date',l:'Due date',t:'date'},
    {k:'status',l:'Status',t:'select',o:['Not started','In progress'],hint:'Review and completion are set by sign-off'},
    {k:'result',l:'Conclusion',t:'select',o:['Not concluded','Effective','Partially effective','Ineffective']},
    {k:'notes',l:'Workpaper notes / results of testing',t:'area',w:1}]},
  evidence:{label:'Evidence request', fields:[
    {k:'title',l:'Evidence / request',req:1},{k:'workpaper_id',l:'Supports workpaper',t:'ref',ref:'workpapers'},{k:'purpose',l:'Purpose in the test',t:'select',o:PURPOSES},
    {k:'type',l:'Type',t:'select',o:['System report / extract','Screenshot','Configuration export','Policy / procedure','Ticket / approval','Email','Interview notes','Log file','Other']},
    {k:'pbc_status',l:'Request (PBC) status',t:'select',o:['Requested','Received','Accepted','Rejected - resubmit']},
    {k:'requested_from',l:'Requested from'},{k:'requested_on',l:'Requested on',t:'date'},
    {k:'collected_by',l:'Received by'},{k:'collected_on',l:'Received on',t:'date'},
    {k:'notes',l:'Notes (completeness & accuracy checks)',t:'area',w:1},{k:'_files',l:'Attach files',t:'files',w:1}]},
  review_notes:{label:'Review note', fields:[{k:'note',l:'Review note',t:'area',w:1,req:1}]},
  issues:{label:'Issue', fields:[
    {k:'title',l:'Issue title',req:1},{k:'workpaper_id',l:'Raised from workpaper',t:'ref',ref:'workpapers'},
    {k:'condition',l:'Condition (what we found)',t:'area',w:1},{k:'criteria',l:'Criteria (what should be)',t:'area',w:1},
    {k:'cause',l:'Cause',t:'area'},{k:'effect',l:'Effect / risk',t:'area'},
    {k:'likelihood',l:'Likelihood',t:'select',o:L5},{k:'impact',l:'Impact',t:'select',o:I5},
    {k:'recommendation',l:'Recommendation',t:'area',w:1},
    {k:'owner_id',l:'Management owner',t:'user',all:1,hint:'Auditee users see and respond to issues they own'},{k:'due_date',l:'Remediation due',t:'date'},
    {k:'status',l:'Status',t:'select',o:['Open','Remediation in progress','Ready for validation','Closed','Risk accepted']},
    {k:'response',l:'Management response / action plan',t:'area',w:1}]},
  time_entries:{label:'Time entry', fields:[
    {k:'date',l:'Date',t:'date',req:1},{k:'hours',l:'Hours',t:'number',req:1},{k:'user_id',l:'Staff',t:'user',mgmt:1},
    {k:'activity',l:'Activity',t:'select',o:['Planning','Fieldwork','Review','Reporting','Follow-up','Admin']},{k:'notes',l:'Notes',t:'area',w:1}]},
  setting_checks:{label:'Setting check', fields:[
    {k:'label',l:'Setting',req:1,list:['Minimum password length','Enforce password history','Maximum password age','Minimum password age',
      'Account lockout threshold','Account lockout duration','Password must meet complexity requirements','Store passwords using reversible encryption']},
    {k:'match_text',l:'Text to look for in the evidence',hint:'As the setting is labelled on screen. Leave blank to use the setting name.'},
    {k:'operator',l:'Requirement',t:'select',req:1,o:[['>=','at least (≥)'],['<=','at most (≤)'],['=','equal to'],['!=','not equal to']]},
    {k:'expected',l:'Required value',req:1,hint:'e.g. 12, or Enabled'},{k:'unit',l:'Unit',hint:'e.g. characters, days'},
    {k:'file_id',l:'Read the actual value from',t:'wpfile',hint:'Leave blank to search all screenshots and documents on this test'},
    {k:'policy_ref',l:'Policy reference',t:'area',w:1,hint:'Where the requirement comes from, e.g. IS-04 section 3.1'}]},
  users:{label:'User', fields:[
    {k:'username',l:'Username',req:1,newOnly:1},{k:'name',l:'Full name',req:1},{k:'email',l:'Email',t:'email'},
    {k:'role',l:'Role',t:'select',req:1,o:[['admin','Administrator'],['manager','Audit manager (reviewer)'],['auditor','Auditor'],['auditee','Auditee (issue owner)']]},
    {k:'active',l:'Account',t:'select',o:[['1','Active'],['0','Disabled']],editOnly:1},
    {k:'password',l:'Password',t:'password',hint:'New users and resets must change it at next sign-in. Minimum 10 characters.'}]}
};

/* ---------- ITGC control library ---------- */
const LIBRARY = [
  ['AC-01','User access provisioning','Logical access','New user access is requested, approved by an appropriate manager and granted consistent with the approval.','As needed','Obtain list of users created in the period; sample new users; inspect approved request predates access and matches role granted.'],
  ['AC-02','Timely removal of terminated users','Logical access','Access for terminated employees is revoked within the defined SLA (e.g. 1 business day).','As needed','Obtain HR termination list; compare to system user list and last-logon dates; for a sample, confirm removal date within SLA.'],
  ['AC-03','Periodic user access review','Logical access','Application owners review user access quarterly and remove inappropriate access.','Quarterly','Inspect review evidence for sampled quarters: completeness of the listing, reviewer sign-off, and removals actioned.'],
  ['AC-04','Privileged access restriction','Privileged access','Administrative/superuser access is limited to authorised personnel with a business need.','Quarterly','Obtain admin account listing; validate each account to job role and approval; check for generic/shared accounts.'],
  ['AC-05','Password / authentication settings','Logical access','Authentication is enforced in line with policy (MFA, length, lockout).','Automated','Inspect system configuration against policy; test of one (automated control) plus baseline of change history.'],
  ['CM-01','Change authorisation & testing','Change management','Changes to production are tested and approved before migration.','As needed','Obtain population of production changes; sample; inspect testing evidence and approval prior to deployment date.'],
  ['CM-02','Segregation of duties in deployment','Change management','Developers cannot migrate their own changes to production.','Automated','Inspect deployment tool permissions; compare developer list to users with deploy rights.'],
  ['CM-03','Emergency changes','Change management','Emergency changes are approved retrospectively within the defined window.','As needed','Sample emergency changes; inspect post-implementation approval within SLA.'],
  ['OP-01','Job scheduling & failure monitoring','IT operations / job scheduling','Batch job failures are detected, logged and resolved.','Daily','Sample days; inspect job logs and tickets for failed jobs and their resolution.'],
  ['OP-02','Backup completion & restore testing','Backup & recovery','Backups are performed per schedule and restores are tested periodically.','Daily','Sample backup logs for success; inspect evidence of the most recent restore test.'],
  ['NS-01','Firewall rule review','Network security','Firewall rules are reviewed periodically and unnecessary rules removed.','Annual','Inspect last rule review, approvals, and follow-up on rules flagged for removal.'],
  ['IM-01','Security incident management','Incident management','Security incidents are logged, classified, escalated and resolved per procedure.','As needed','Sample incidents; inspect classification, escalation and closure evidence against procedure timelines.']
];

/* ---------- API ---------- */
async function api(method, path, body, file){
  const opt = {method, headers:{'X-Requested-With':'fetch'}, credentials:'same-origin'};
  if (file){ opt.body = file; opt.headers['Content-Type'] = file.type || 'application/octet-stream'; opt.headers['X-Filename'] = encodeURIComponent(file.name); }
  else if (body !== undefined){ opt.body = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
  const r = await fetch('/api/' + path, opt);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== 'login' && S.me){ S.me = null; render(); }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}
const TABLES = ['universe','plan','engagements','risks','workpapers','evidence','files','review_notes','issues','time_entries',
  'samples','analyses','setting_checks'];

/* ---------- State & helpers ---------- */
const S = {att:{purpose:PURPOSES[0], desc:''}, busy:0, me:null, users:[], sec:'home', tab:'overview', eng:null, wp:null, year:String(new Date().getFullYear()), filt:{}};
TABLES.forEach(t => S[t] = []);
const $ = sel => document.querySelector(sel);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const byId = (t, id) => S[t].find(x => x.id === id);
const inEng = t => S[t].filter(x => x.engagement_id === S.eng);
const uname = id => { const u = S.users.find(x => x.id === id); return u ? u.name : ''; };
const isStaff = () => S.me && S.me.role !== 'auditee';
const isMgmt = () => S.me && ['admin','manager'].includes(S.me.role);
const fmtTs = ts => ts ? new Date(ts).toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'}) : '';
const fmtSize = n => (n = +n) < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const badge = (v, cls) => v ? `<span class="badge ${cls || ''}">${esc(v)}</span>` : '';
const crit = r => r.likelihood && r.impact ? criticality(r.likelihood, r.impact) : '';
const critBadge = r => crit(r) ? badge(crit(r), 'b-' + crit(r)) : '<span class="muted">unrated</span>';
const resultBadge = v => badge(v, 'b-' + String(v || '').split(' ')[0]);
const due = (d, st) => d ? `<span class="${isOverdue(d, st) ? 'over' : ''}"${isOverdue(d, st) ? ' title="Overdue"' : ''}>${esc(d)}</span>` : '';
const hours = rows => rows.reduce((s, r) => s + (Number(r.hours) || 0), 0);
const openNotes = wpId => S.review_notes.filter(n => n.workpaper_id === wpId && n.status !== 'Cleared');
function toast(msg, err){
  const t = $('#toast'); t.textContent = msg; t.className = 'show' + (err ? ' err' : '');
  clearTimeout(toast.h); toast.h = setTimeout(() => t.className = '', err ? 5000 : 2500);
}
async function run(fn){ try { await fn(); } catch (e) { toast(e.message, true); } }

async function loadAll(){
  S.me = await api('GET', 'me');
  S.users = await api('GET', 'users');
  if (isStaff()) S.ocr = await api('GET', 'ocr');
  const tabs = isStaff() ? TABLES : ['engagements', 'issues'];
  const res = await Promise.all(tabs.map(t => api('GET', t)));
  tabs.forEach((t, i) => S[t] = res[i]);
  if (S.eng && !byId('engagements', S.eng)){ S.eng = null; S.wp = null; if (S.sec === 'eng') S.sec = 'home'; }
}
async function refresh(){ await loadAll(); render(); }

/* ---------- Generic form dialog ---------- */
const dlg = $('#dlg');
function optionList(f, v){
  if (f.t === 'select'){ const o = f.o.map(o => Array.isArray(o) ? o : [o, o]); return v && !o.some(x => x[0] === String(v)) ? [[v, v], ...o] : o; }
  if (f.t === 'wpfile') return S.files.filter(x => x.ocr_status === 'done' && (byId('evidence', x.evidence_id) || {}).workpaper_id === S.wp).map(x => [x.id, x.name]);
  if (f.t === 'user') return S.users.filter(u => u.active && (f.all || u.role !== 'auditee')).map(u => [u.id, u.name + (u.role === 'auditee' ? ' (auditee)' : '')]);
  const rows = f.ref === 'universe' ? S.universe : inEng(f.ref);
  return rows.map(r => [r.id, f.ref === 'workpapers' ? `${r.ref} - ${r.title}` : r.area || r.name]);
}
function fieldHtml(f, v, isNew){
  if ((f.newOnly && !isNew) || (f.editOnly && isNew) || (f.mgmt && !isMgmt())) return '';
  const id = 'f_' + f.k, req = f.req && !(f.t === 'password' && !isNew) ? ' required' : '';
  let inp;
  if (['select','user','ref','wpfile'].includes(f.t)){
    inp = `<select id="${id}" name="${f.k}"${req}><option value=""></option>${optionList(f, v).map(([val, lab]) =>
      `<option value="${esc(val)}"${String(v ?? '') === String(val) ? ' selected' : ''}>${esc(lab)}</option>`).join('')}</select>`;
  } else if (f.t === 'area'){
    inp = `<textarea id="${id}" name="${f.k}"${req}>${esc(v)}</textarea>`;
  } else if (f.t === 'files'){
    inp = `<input type="file" id="${id}" multiple>`;
  } else {
    inp = `<input id="${id}" name="${f.k}" type="${f.t || 'text'}" value="${f.t === 'password' ? '' : esc(v)}"${req}${f.t === 'number' ? ' step="any" min="0"' : ''}${f.list ? ` list="dl_${f.k}"` : ''}${f.t === 'password' ? ' autocomplete="new-password" minlength="10"' : ''}>` +
      (f.list ? `<datalist id="dl_${f.k}">${f.list.map(o => `<option value="${esc(o)}">`).join('')}</datalist>` : '');
  }
  return `<div class="${f.w ? 'wide' : ''}"><label for="${id}">${esc(f.l)}${req ? ' *' : ''}</label>${inp}${f.hint ? `<div class="hint">${esc(f.hint)}</div>` : ''}</div>`;
}
function modal(title, inner, onSubmit, opts = {}){
  dlg.classList.remove('wide');
  dlg.innerHTML = `<form><h3>${esc(title)}</h3>${inner}<div id="calc" class="muted" style="margin-top:8px"></div>
    <div class="dlgbar">${opts.noCancel || opts.info ? '' : '<button type="button" class="btn ghost" data-close>Cancel</button>'}<button class="btn" id="saveBtn">${esc(opts.ok || 'Save')}</button></div></form>`;
  const form = dlg.querySelector('form');
  form.onsubmit = async e => {
    e.preventDefault();
    const btn = $('#saveBtn'); btn.disabled = true;
    try { await onSubmit(form); dlg.close(); } catch (err) { toast(err.message, true); } finally { btn.disabled = false; }
  };
  dlg.oncancel = opts.noCancel ? (e => e.preventDefault()) : null;
  dlg.showModal();
  return form;
}
// Opens the create/edit form for a record; returns after saving.
function openForm(table, rec, defaults, after){
  const sc = SCHEMAS[table], isNew = !rec, base = rec || Object.assign({}, defaults);
  const form = modal(`${isNew ? 'New' : 'Edit'} ${sc.label.toLowerCase()}`,
    `<div class="fields">${sc.fields.map(f => fieldHtml(f, f.k === 'active' ? (base.active ? '1' : '0') : base[f.k], isNew)).join('')}</div>`,
    async form => {
      const d = {...(isNew ? defaults : {}), ...Object.fromEntries(new FormData(form))};
      let saved;
      if (table === 'users'){
        if (!d.password) delete d.password;
        if ('active' in d) d.active = d.active === '1';
        saved = isNew ? await api('POST', 'users', d) : await api('PUT', 'users/' + rec.id, d);
      } else {
        if (sc.fields.some(f => f.k === 'engagement_id') || !['universe','plan','engagements'].includes(table)) d.engagement_id = base.engagement_id || S.eng;
        saved = isNew ? await api('POST', table, d) : await api('PUT', `${table}/${rec.id}`, {...d, _version:rec.updated_at});
        const files = form.querySelector('#f__files')?.files || [];
        for (const file of files) await api('POST', `evidence/${saved.id}/files`, undefined, file);
      }
      toast('Saved');
      await loadAll();
      if (after) await after(saved);
      render();
    });
  const calc = $('#calc');
  const upd = () => { const l = form.likelihood?.value, i = form.impact?.value;
    calc.innerHTML = l && i ? `Risk score ${riskScore(l, i)} / 25 &rarr; ${badge(criticality(l, i), 'b-' + criticality(l, i))}` : ''; };
  form.addEventListener('input', upd); upd();
  if (table === 'workpapers') ['f_frequency', 'f_key_control'].forEach(id => form.querySelector('#' + id).addEventListener('change', () => {
    if (form.frequency.value) form.sample_size.value = suggestedSample(form.frequency.value, form.key_control.value === 'Yes');
  }));
}

/* ---------- Generic table ---------- */
function table(cols, rows, opts = {}){
  if (!rows.length) return `<div class="empty">${esc(opts.empty || 'Nothing here yet.')}</div>`;
  return `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th>${esc(c[0])}</th>`).join('')}${opts.actions ? '<th></th>' : ''}</tr></thead><tbody>
    ${rows.map(r => `<tr${opts.open ? ` class="click" data-open="${opts.open}" data-id="${r.id}"` : ''}>${cols.map(c => `<td>${c[1](r)}</td>`).join('')}${opts.actions ? `<td class="actions">${opts.actions(r)}</td>` : ''}</tr>`).join('')}
  </tbody></table></div>`;
}
const editDel = (t, r, canDel = true) => `<button class="link" data-edit="${t}" data-id="${r.id}">Edit</button>${canDel ? `<button class="link" data-del="${t}" data-id="${r.id}">Delete</button>` : ''}`;

function heatmap(issues){
  const colour = s => s >= 20 ? 'var(--crit)' : s >= 12 ? 'var(--high)' : s >= 6 ? 'var(--med)' : 'var(--low)';
  let h = '<div class="heat">';
  for (let imp = 5; imp >= 1; imp--){
    h += `<div class="ax">${imp}</div>`;
    for (let l = 1; l <= 5; l++){ const n = issues.filter(i => +i.likelihood === l && +i.impact === imp).length;
      h += `<div style="background:${colour(l * imp)};opacity:${n ? 1 : .28};color:#fff;font-weight:700">${n || ''}</div>`; }
  }
  return h + '<div class="ax"></div>' + [1,2,3,4,5].map(l => `<div class="ax">${l}</div>`).join('') +
    '</div><div class="muted" style="font-size:12px;text-align:center">Likelihood &rarr; (rows: Impact)</div>';
}
const critCounts = issues => `<div class="legend" style="gap:8px">${LEVELS.map(l => `<span class="badge b-${l}">${l}: ${issues.filter(i => crit(i) === l).length}</span>`).join('')}</div>`;
const openIssues = rows => rows.filter(i => !['Closed', 'Risk accepted'].includes(i.status));
const stat = (n, l, warn) => `<div class="card stat"><div class="n"${warn && n ? ' style="color:var(--crit)"' : ''}>${n}</div><div class="l">${esc(l)}</div></div>`;
const kv = rows => `<div class="tablewrap"><table class="kv">${rows.filter(r => r[1]).map(r => `<tr><th>${esc(r[0])}</th><td>${r[2] ? r[1] : esc(r[1])}</td></tr>`).join('')}</table></div>`;

/* ---------- Views ---------- */
const SECTIONS = () => isStaff()
  ? [['home','Home'],['universe','Audit universe'],['plan','Annual plan'],['engs','Engagements'],['tracker','Issue tracker'], ...(isMgmt() ? [['admin','Admin']] : [])]
  : [['myissues','My issues']];
const ENG_TABS = () => [['overview','Overview'],['planning','Planning'],['workpapers','Workpapers'],['evidence','Evidence & PBC'],['notes','Review notes'],
  ['issues','Issues'],['time','Time'],['report','Report'], ...(isMgmt() ? [['history','History']] : [])];

const V = {
  home(){
    const me = S.me.id, active = S.engagements.filter(e => e.status !== 'Closed');
    const myWp = S.workpapers.filter(w => w.assigned_to === me && w.status !== 'Complete');
    const notesForMe = S.review_notes.filter(n => n.status === 'Open' && (byId('workpapers', n.workpaper_id) || {}).assigned_to === me);
    const toReview = isMgmt() ? S.workpapers.filter(w => w.status === 'Ready for review' && w.prepared_by !== me) : [];
    const myResp = S.review_notes.filter(n => n.status === 'Responded' && n.created_by === me);
    const oi = openIssues(S.issues), overdue = oi.filter(i => isOverdue(i.due_date, i.status));
    const engName = id => esc((byId('engagements', id) || {}).name);
    const tasks = [
      ...myWp.map(w => ['Workpaper to complete', `${w.ref} ${w.title}`, w.engagement_id, w.id, w.due_date]),
      ...notesForMe.map(n => ['Review note to answer', n.note, n.engagement_id, n.workpaper_id, '']),
      ...toReview.map(w => ['Workpaper to review', `${w.ref} ${w.title}`, w.engagement_id, w.id, w.due_date]),
      ...myResp.map(n => ['Review note response to clear', n.note, n.engagement_id, n.workpaper_id, ''])];
    return `<div class="grid">${stat(active.length, 'Active engagements')}${stat(myWp.length, 'My open workpapers')}${stat(notesForMe.length + myResp.length, 'Review notes needing me')}
      ${isMgmt() ? stat(toReview.length, 'Workpapers awaiting review') : ''}${stat(oi.length, 'Open issues')}${stat(overdue.length, 'Overdue issues', 1)}</div>
      <div class="card"><h2>My tasks</h2>${table([['Task', t => esc(t[0])], ['Item', t => esc(String(t[1]).slice(0, 120))], ['Engagement', t => engName(t[2])], ['Due', t => due(t[4])]],
        tasks.map(t => Object.assign(t, {id:t[3]})), {open:'wp', empty:'You are all caught up.'})}</div>
      <div class="two"><div class="card" style="grid-column:span 2;min-width:0"><h2>Engagement portfolio</h2>${portfolio(active)}</div></div>
      <div class="two"><div class="card"><h2>Open issues by criticality</h2>${critCounts(oi)}<div style="margin-top:12px">${heatmap(oi)}</div></div>
        <div class="card"><h2>Overdue issues</h2>${table([['Issue', i => esc(i.title)], ['Owner', i => esc(uname(i.owner_id))], ['Due', i => due(i.due_date, i.status)], ['', critBadge]], overdue, {open:'issue', empty:'Nothing overdue.'})}</div></div>`;
  },
  universe(){
    const rows = [...S.universe].sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact));
    return `<div class="card"><div class="toolbar"><h2>Audit universe</h2>${isMgmt() ? '<button class="btn" data-new="universe">Add entity</button>' : ''}</div>
      <p class="muted" style="margin-top:0">Everything that could be audited, rated by risk to drive the annual plan. Highest risk first.</p>
      ${table([['Entity', u => `<b>${esc(u.name)}</b><div class="muted">${esc(u.category)}</div>`], ['Owner', u => esc(u.owner)], ['Risk', critBadge],
        ['Cycle', u => esc(u.frequency)], ['Last audited', u => esc(u.last_audited)], ['Next due', u => due(nextAuditDue(u))],
        ['Planned', u => S.plan.filter(p => p.universe_id === u.id && !CLOSED.includes(p.status)).map(p => esc(`${p.year} ${p.quarter || ''}`)).join(', ')]], rows,
        {actions: isMgmt() ? u => `<button class="link" data-toplan="${u.id}">Add to plan</button>${editDel('universe', u)}` : null})}</div>`;
  },
  plan(){
    const years = [...new Set([S.year, ...S.plan.map(p => p.year)])].filter(Boolean).sort();
    const rows = S.plan.filter(p => p.year === S.year).sort((a, b) => (a.quarter || 'Q9').localeCompare(b.quarter || 'Q9'));
    const budget = rows.reduce((s, p) => s + (+p.budget_hours || 0), 0);
    const actual = rows.reduce((s, p) => s + hours(S.time_entries.filter(t => p.engagement_id && t.engagement_id === p.engagement_id)), 0);
    return `<div class="card"><div class="toolbar"><h2>Annual audit plan</h2>
      <select id="yearSel" style="width:auto">${years.map(y => `<option${y === S.year ? ' selected' : ''}>${esc(y)}</option>`).join('')}<option value="__next">+ Add year</option></select>
      ${isMgmt() ? '<button class="btn" data-new="plan">Add plan item</button>' : ''}</div>
      <div class="grid" style="margin-bottom:12px">${stat(rows.length, 'Planned audits')}${stat(rows.filter(p => p.status === 'Completed').length, 'Completed')}
        ${stat(budget, 'Budget hours')}${stat(actual, 'Actual hours (linked engagements)')}</div>
      ${table([['Quarter', p => esc(p.quarter)], ['Audit', p => `<b>${esc(p.title)}</b><div class="muted">${esc((byId('universe', p.universe_id) || {}).name)}</div>`],
        ['Risk', p => { const u = byId('universe', p.universe_id); return u ? critBadge(u) : ''; }], ['Lead', p => esc(uname(p.lead_id))],
        ['Budget h', p => esc(p.budget_hours)], ['Status', p => badge(p.status)],
        ['Engagement', p => p.engagement_id && byId('engagements', p.engagement_id) ? `<button class="link" data-goeng="${p.engagement_id}">${esc(byId('engagements', p.engagement_id).name)}</button>`
          : isMgmt() ? `<button class="link" data-mkeng="${p.id}">Start engagement</button>` : '']], rows,
        {actions: isMgmt() ? p => editDel('plan', p) : null, empty:'No audits planned for this year.'})}</div>`;
  },
  engs(){
    return `<div class="card"><div class="toolbar"><h2>Engagements</h2>${isMgmt() ? '<button class="btn" data-new="engagements">New engagement</button>' : ''}</div>
      ${portfolio(S.engagements)}</div>`;
  },
  tracker(){
    const f = S.filt;
    let rows = S.issues.filter(i => (!f.status || (f.status === 'open' ? !['Closed','Risk accepted'].includes(i.status) : i.status === f.status)) && (!f.crit || crit(i) === f.crit));
    rows.sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact));
    const sel = (k, opts) => `<select data-filt="${k}">${opts.map(([v, l]) => `<option value="${v}"${(f[k] || '') === v ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
    return `<div class="card"><div class="toolbar"><h2>Issue tracker (all engagements)</h2>
      <div class="filters">${sel('status', [['', 'All statuses'], ['open', 'Open (any stage)'], ...SCHEMAS.issues.fields.find(x => x.k === 'status').o.map(s => [s, s])])}
      ${sel('crit', [['', 'All criticality'], ...LEVELS.map(l => [l, l])])}</div><button class="btn ghost" data-csv="issues">Export CSV</button></div>
      ${issueTable(rows, true)}</div>`;
  },
  admin(){
    return (S.me.role === 'admin' ? `<div class="card"><div class="toolbar"><h2>Users</h2><button class="btn" data-new="users">Add user</button></div>
      ${table([['Name', u => `<b>${esc(u.name)}</b><div class="muted">${esc(u.username)}</div>`], ['Email', u => esc(u.email)], ['Role', u => badge(u.role)],
        ['Status', u => u.active ? 'Active' : '<span class="muted">Disabled</span>']], S.users, {actions:u => `<button class="link" data-edit="users" data-id="${u.id}">Edit</button>`})}
      <p class="muted">Roles: <b>Administrator</b> manages users and everything else. <b>Audit manager</b> owns the universe, plan and engagements and signs off as reviewer.
      <b>Auditor</b> prepares workpapers, evidence and issues. <b>Auditee</b> only sees issues they own and records management responses.</p></div>` : '') +
      ocrAdminCard() + `<div class="card"><div class="toolbar"><h2>Audit trail</h2><button class="btn ghost" data-loadlog="all">Load latest 500 events</button></div><div id="logBox" class="muted">Every create, edit, delete, sign-off, upload, download and sign-in is recorded.</div></div>`;
  },
  myissues(){
    const rows = [...S.issues].sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact));
    return `<div class="card"><h2>Issues assigned to you</h2><p class="muted" style="margin-top:0">Open an issue to read the finding and record your action plan or remediation update.</p>
      ${table([['Criticality', critBadge], ['Issue', i => `<b>${esc(i.title)}</b>`], ['Audit', i => esc((byId('engagements', i.engagement_id) || {}).name)],
        ['Due', i => due(i.due_date, i.status)], ['Status', i => badge(i.status)]], rows, {open:'myissue', empty:'No issues are assigned to you.'})}</div>`;
  },
  eng(){
    const e = byId('engagements', S.eng);
    if (S.wp) return wpView(e);
    return EV[S.tab](e);
  }
};

function portfolio(engs){
  return table([['Engagement', e => `<b>${esc(e.name)}</b><div class="muted">${esc(e.auditee)}</div>`], ['Phase', e => badge(e.status)], ['Lead', e => esc(uname(e.lead_id))],
    ['Fieldwork', e => e.field_start ? `${esc(e.field_start)} &ndash; ${due(e.field_end, e.status === 'Closed' ? 'Closed' : '')}` : ''],
    ['Workpapers', e => { const w = S.workpapers.filter(x => x.engagement_id === e.id), c = w.filter(x => x.status === 'Complete').length;
      return w.length ? `${c}/${w.length} complete<div class="bar" style="width:100px"><span style="width:${c / w.length * 100}%;background:var(--low)"></span></div>` : '<span class="muted">none</span>'; }],
    ['Open notes', e => S.review_notes.filter(n => n.engagement_id === e.id && n.status !== 'Cleared').length || ''],
    ['Open issues', e => LEVELS.map(l => { const n = openIssues(S.issues).filter(i => i.engagement_id === e.id && crit(i) === l).length; return n ? badge(`${n} ${l}`, 'b-' + l) : ''; }).join(' ')],
    ['Hours', e => { const a = hours(S.time_entries.filter(t => t.engagement_id === e.id)); return e.budget_hours ? `<span class="${a > +e.budget_hours ? 'over' : ''}">${a}</span> / ${esc(e.budget_hours)}` : a || ''; }]],
    engs, {open:'eng', empty:'No engagements yet.'});
}
function issueTable(rows, showEng){
  return table([['Criticality', i => critBadge(i) + (i.likelihood ? `<div class="muted">score ${riskScore(i.likelihood, i.impact)}</div>` : '')],
    ['Issue', i => `<b>${esc(i.title)}</b><div class="muted">${esc((i.condition || '').slice(0, 140))}</div>`],
    ...(showEng ? [['Engagement', i => esc((byId('engagements', i.engagement_id) || {}).name)]] : [['Workpaper', i => esc((byId('workpapers', i.workpaper_id) || {}).ref)]]),
    ['Owner', i => esc(uname(i.owner_id))], ['Due', i => due(i.due_date, i.status)], ['Status', i => badge(i.status)]], rows, {open:'issue', empty:'No issues.'});
}

/* Engagement workspace tabs */
const EV = {
  overview(e){
    const W = inEng('workpapers'), I = openIssues(inEng('issues')), N = inEng('review_notes').filter(n => n.status !== 'Cleared');
    const st = s => W.filter(w => w.status === s).length, done = st('Complete');
    const seg = (n, c) => W.length ? `<span style="width:${n / W.length * 100}%;background:${c}"></span>` : '';
    const actual = hours(inEng('time_entries'));
    const pbc = inEng('evidence').filter(x => ['Requested', 'Rejected - resubmit'].includes(x.pbc_status));
    return `<div class="card"><div class="toolbar"><h2>${esc(e.name)}</h2>${badge(e.status)}${canEditEng(e) ? `<button class="btn ghost" data-edit="engagements" data-id="${e.id}">Edit engagement</button>` : ''}</div>
      <div class="muted">${[e.auditee, e.framework, e.period_start && `Period ${e.period_start} to ${e.period_end}`, e.lead_id && 'Lead: ' + uname(e.lead_id), e.team && 'Team: ' + e.team].filter(Boolean).map(esc).join(' &middot; ')}</div></div>
      <div class="grid">${stat(W.length, 'Workpapers')}${stat(W.length ? Math.round(done / W.length * 100) + '%' : '0%', 'Reviewed & complete')}${stat(N.length, 'Open review notes', 1)}
        ${stat(pbc.length, 'Outstanding PBC requests', 1)}${stat(I.length, 'Open issues')}${stat(`${actual}${e.budget_hours ? ' / ' + esc(e.budget_hours) : ''}`, 'Hours actual / budget')}</div>
      <div class="two"><div class="card"><h2>Workpaper progress</h2>
          <div class="bar">${seg(done, 'var(--low)')}${seg(st('Ready for review'), 'var(--accent)')}${seg(st('In progress'), 'var(--med)')}</div>
          <div class="legend"><span><i style="background:var(--low)"></i>Complete ${done}</span><span><i style="background:var(--accent)"></i>Ready for review ${st('Ready for review')}</span>
          <span><i style="background:var(--med)"></i>In progress ${st('In progress')}</span><span><i style="background:var(--chip)"></i>Not started ${st('Not started')}</span></div>
          <h2 style="margin-top:16px">Conclusions</h2>
          <div class="legend">${['Effective','Partially effective','Ineffective','Not concluded'].map(r => `<span>${esc(r)}: <b>${W.filter(w => (w.result || 'Not concluded') === r).length}</b></span>`).join('')}</div></div>
        <div class="card"><h2>Open issues by criticality</h2>${critCounts(I)}<div style="margin-top:12px">${heatmap(I)}</div></div></div>`;
  },
  planning(e){
    const R = inEng('risks').sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact));
    return `<div class="card"><div class="toolbar"><h2>Audit plan &amp; scope</h2>${isMgmt() ? `<button class="link" data-del="engagements" data-id="${e.id}">Delete engagement</button>` : ''}
        ${canEditEng(e) ? `<button class="btn ghost" data-edit="engagements" data-id="${e.id}">Edit</button>` : ''}</div>
      ${kv([['Engagement', e.name], ['Auditee', e.auditee], ['Auditable entity', (byId('universe', e.universe_id) || {}).name], ['Framework', e.framework],
        ['Audit period', e.period_start && `${e.period_start} to ${e.period_end}`], ['Fieldwork', e.field_start && `${e.field_start} to ${e.field_end}`],
        ['Lead', uname(e.lead_id)], ['Team', e.team], ['Budget hours', e.budget_hours], ['Objectives', e.objectives], ['Scope', e.scope], ['Out of scope', e.out_of_scope]])}</div>
      <div class="card"><div class="toolbar"><h2>Risk assessment</h2><button class="btn" data-new="risks">Add risk area</button></div>
      <p class="muted" style="margin-top:0">Rate inherent risk to focus testing. Highest-rated areas appear first.</p>
      ${table([['Area', r => `<b>${esc(r.area)}</b>`], ['Systems', r => esc(r.system)], ['L x I', r => r.likelihood ? `${r.likelihood} x ${r.impact} = ${riskScore(r.likelihood, r.impact)}` : ''],
        ['Rating', critBadge], ['Workpapers', r => inEng('workpapers').filter(w => w.risk_id === r.id).length], ['Planned response', r => esc(r.response)]], R, {actions:r => editDel('risks', r)})}</div>`;
  },
  workpapers(){
    const W = inEng('workpapers').sort((a, b) => (a.ref || '').localeCompare(b.ref || ''));
    const so = (by, at) => by ? `<span title="${esc(fmtTs(at))}">&#10003; ${esc(uname(by))}</span>` : '<span class="muted">&ndash;</span>';
    return `<div class="card"><div class="toolbar"><h2>Workpapers</h2><button class="btn ghost" id="libBtn">Add from ITGC library</button><button class="btn" data-new="workpapers">New workpaper</button></div>
      ${table([['Ref', w => `<b style="white-space:nowrap">${esc(w.ref)}</b>`], ['Control', w => esc(w.title) + (w.key_control === 'Yes' ? ' <span class="badge">Key</span>' : '')],
        ['Assigned', w => esc(uname(w.assigned_to))], ['Sample', w => esc(w.sample_size) + (+w.exceptions > 0 ? ` <span class="over">(${esc(w.exceptions)} exc.)</span>` : '')],
        ['Evidence', w => { const n = wpFiles(w.id).length;
          return `<span style="white-space:nowrap">${n ? `&#128206; ${n}` : '<span class="muted">none</span>'} <label class="link attach" title="Attach files to this test">Attach<input type="file" multiple hidden data-attach="${w.id}"></label></span>`; }], ['Notes', w => { const n = openNotes(w.id).length; return n ? `<span class="over">${n} open</span>` : ''; }],
        ['Due', w => due(w.due_date, w.status)], ['Status', w => badge(w.status)], ['Conclusion', w => resultBadge(w.result)],
        ['Prepared', w => so(w.prepared_by, w.prepared_at)], ['Reviewed', w => so(w.reviewed_by, w.reviewed_at)]], W, {open:'wp'})}</div>`;
  },
  evidence(){
    const E = inEng('evidence');
    return `<div class="card"><div class="toolbar"><h2>Evidence &amp; PBC requests</h2><button class="btn" data-new="evidence">New request / evidence</button></div>
      <p class="muted" style="margin-top:0">Files are stored on the server with a SHA-256 fingerprint so you can show they were not altered after collection. Every upload and download is logged.</p>
      <label for="evSearch" class="muted" style="font-size:12px;font-weight:600">Search evidence, including text read from screenshots and PDFs</label>
      <input id="evSearch" type="search" value="${esc(S.q || '')}" placeholder="e.g. lockout threshold, leavers, MFA"><div id="evResults" style="margin:8px 0 16px"></div>
      ${evidenceTable(E)}</div>`;
  },
  notes(){
    const N = inEng('review_notes').sort((a, b) => ['Open','Responded','Cleared'].indexOf(a.status) - ['Open','Responded','Cleared'].indexOf(b.status));
    return `<div class="card"><h2>Review notes</h2><p class="muted" style="margin-top:0">Reviewers raise notes on workpapers; preparers respond; the reviewer clears them. Open notes block review sign-off.</p>
      ${table([['Status', n => badge(n.status)], ['Workpaper', n => { const w = byId('workpapers', n.workpaper_id); return w ? `<b>${esc(w.ref)}</b> ${esc(w.title)}` : ''; }],
        ['Note', n => `${esc(n.note)}<div class="muted">${esc(uname(n.created_by))}, ${esc(fmtTs(n.created_at))}</div>`],
        ['Response', n => n.response ? `${esc(n.response)}<div class="muted">${esc(uname(n.responded_by))}</div>` : '']], N, {open:'wpnote', empty:'No review notes.'})}</div>`;
  },
  issues(){
    return `<div class="card"><div class="toolbar"><h2>Issues</h2><button class="btn" data-new="issues">New issue</button></div>
      ${issueTable(inEng('issues').sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact)))}</div>
      <div class="card"><h2>How criticality is rated</h2><p class="muted" style="margin-top:0">Score = Likelihood (1-5) x Impact (1-5).</p>
        <div class="legend" style="gap:8px"><span class="badge b-Critical">Critical 20-25</span><span class="badge b-High">High 12-19</span><span class="badge b-Medium">Medium 6-11</span><span class="badge b-Low">Low 1-5</span></div></div>`;
  },
  time(e){
    const T = inEng('time_entries').sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    const people = [...new Set(T.map(t => t.user_id))];
    const acts = SCHEMAS.time_entries.fields.find(f => f.k === 'activity').o;
    const total = hours(T);
    return `<div class="two"><div class="card"><h2>Budget vs actual</h2>
        <div class="grid">${stat(e.budget_hours || '-', 'Budget hours')}${stat(total, 'Actual hours')}${stat(e.budget_hours ? Math.round(total / e.budget_hours * 100) + '%' : '-', 'Budget used', total > +e.budget_hours)}</div></div>
      <div class="card"><h2>Hours by person and activity</h2>${people.length ? `<div class="tablewrap"><table><tr><th>Staff</th>${acts.map(a => `<th>${a}</th>`).join('')}<th>Total</th></tr>
        ${people.map(p => `<tr><td>${esc(uname(p))}</td>${acts.map(a => `<td>${hours(T.filter(t => t.user_id === p && t.activity === a)) || ''}</td>`).join('')}<td><b>${hours(T.filter(t => t.user_id === p))}</b></td></tr>`).join('')}</table></div>` : '<div class="empty">No time logged.</div>'}</div></div>
      <div class="card"><div class="toolbar"><h2>Time entries</h2><button class="btn" data-new="time_entries">Log time</button></div>
      ${table([['Date', t => esc(t.date)], ['Staff', t => esc(uname(t.user_id))], ['Activity', t => esc(t.activity)], ['Hours', t => esc(t.hours)], ['Notes', t => esc(t.notes)]], T,
        {actions:t => isMgmt() || t.user_id === S.me.id ? editDel('time_entries', t) : ''})}</div>`;
  },
  report(e){
    const W = inEng('workpapers'), R = inEng('risks'), E = inEng('evidence');
    const I = inEng('issues').sort((a, b) => riskScore(b.likelihood, b.impact) - riskScore(a.likelihood, a.impact));
    const para = (h, v) => v ? `<h3>${h}</h3><p style="white-space:pre-wrap">${esc(v)}</p>` : '';
    const unrev = W.filter(w => w.status !== 'Complete').length;
    return `<div class="card"><div class="toolbar no-print"><h2>Audit report draft</h2><button class="btn ghost" data-csv="workpapers">Workpapers CSV</button><button class="btn ghost" data-csv="engissues">Issues CSV</button><button class="btn" id="printBtn">Print / Save as PDF</button></div>
      ${unrev ? `<p class="over no-print">${unrev} workpaper(s) are not yet reviewed. The report is a draft until all workpapers are signed off.</p>` : ''}
      <h1 style="font-size:20px;margin:0">${esc(e.name)}</h1><p class="muted">${[e.auditee, e.framework, e.period_start && `Period ${e.period_start} to ${e.period_end}`].filter(Boolean).map(esc).join(' &middot; ')} &middot; Generated ${today()}</p>
      <h3>Executive summary</h3><p>We tested <b>${W.length}</b> controls across <b>${R.length}</b> risk areas, supported by <b>${E.length}</b> evidence items.
      ${W.filter(w => w.result === 'Effective').length} controls were effective, ${W.filter(w => w.result === 'Partially effective').length} partially effective and ${W.filter(w => w.result === 'Ineffective').length} ineffective.
      We raised <b>${I.length}</b> issues: ${LEVELS.map(l => `${I.filter(i => crit(i) === l).length} ${l.toLowerCase()}`).join(', ')}.</p>
      ${para('Objectives', e.objectives)}${para('Scope', e.scope)}${para('Out of scope / limitations', e.out_of_scope)}
      <h3>Detailed findings</h3>${I.length ? I.map((i, n) => `<div class="card"><div class="toolbar"><h2>${n + 1}. ${esc(i.title)}</h2>${critBadge(i)}</div>
        ${[['Condition', i.condition], ['Criteria', i.criteria], ['Cause', i.cause], ['Effect', i.effect], ['Recommendation', i.recommendation], ['Management response', i.response]]
          .filter(x => x[1]).map(x => `<p><b>${x[0]}:</b> <span style="white-space:pre-wrap">${esc(x[1])}</span></p>`).join('')}
        <p class="muted">Owner: ${esc(uname(i.owner_id)) || '-'} &middot; Due: ${esc(i.due_date) || '-'} &middot; Status: ${esc(i.status) || '-'}</p></div>`).join('') : '<p class="muted">No issues raised.</p>'}
      <h3>Controls tested</h3>${table([['Ref', w => esc(w.ref)], ['Control', w => esc(w.title)], ['Method', w => esc(w.test_type)], ['Sample', w => esc(w.sample_size)],
        ['Exceptions', w => esc(w.exceptions)], ['Conclusion', w => resultBadge(w.result)], ['Reviewed by', w => esc(uname(w.reviewed_by))]], W)}</div>`;
  },
  history(e){
    return `<div class="card"><div class="toolbar"><h2>Engagement history</h2><button class="btn ghost" data-loadlog="${e.id}">Load</button></div><div id="logBox" class="muted">Full audit trail for this engagement.</div></div>`;
  }
};
const canEditEng = e => isMgmt() || e.lead_id === S.me.id;

function evidenceTable(E){
  return table([['Evidence', x => `<b>${esc(x.title)}</b><div class="muted">${esc([x.purpose, x.type].filter(Boolean).join(' · '))}</div>`],
    ['Workpaper', x => { const w = byId('workpapers', x.workpaper_id); return w ? esc(w.ref) : '<span class="muted">unlinked</span>'; }],
    ['Request', x => badge(x.pbc_status) + `<div class="muted">${esc(x.requested_from)}${x.requested_on ? ' &middot; ' + esc(x.requested_on) : ''}</div>`],
    ['Received', x => esc(x.collected_on) + (x.collected_by ? `<div class="muted">by ${esc(x.collected_by)}</div>` : '')],
    ['Files', x => S.files.filter(f => f.evidence_id === x.id).map(f => `<div><button class="link" data-file="${f.id}" data-name="${esc(f.name)}">${esc(f.name)}</button> <span class="muted">${fmtSize(f.size)}</span>
      ${isMgmt() || f.created_by === S.me.id ? `<button class="link" data-delfile="${f.id}" title="Remove file">&times;</button>` : ''}
      <div class="mono muted" title="SHA-256 fingerprint">SHA-256 ${esc(f.sha256)}</div>${ocrChip(f)}</div>`).join('') + `<label class="link" style="cursor:pointer">+ Upload<input type="file" multiple hidden data-upload="${x.id}"></label>`]],
    E, {actions:x => editDel('evidence', x), empty:'No evidence yet.'});
}

/* Workpaper detail */
function wpView(e){
  const w = byId('workpapers', S.wp);
  if (!w){ S.wp = null; return EV[S.tab](e); }
  const N = S.review_notes.filter(n => n.workpaper_id === w.id), open = N.filter(n => n.status !== 'Cleared').length;
  const me = S.me.id, signed = w.prepared_by || w.reviewed_by;
  const prep = w.prepared_by ? `<div class="ok"><b>Prepared</b><div>${esc(uname(w.prepared_by))}</div><div class="muted">${esc(fmtTs(w.prepared_at))}</div></div>`
    : `<div><b>Preparer sign-off</b><p class="muted">Confirms testing is complete and the conclusion is supported.</p><button class="btn" data-signoff="prepare">Sign off as preparer</button></div>`;
  const rev = w.reviewed_by ? `<div class="ok"><b>Reviewed</b><div>${esc(uname(w.reviewed_by))}</div><div class="muted">${esc(fmtTs(w.reviewed_at))}</div></div>`
    : `<div><b>Reviewer sign-off</b><p class="muted">${!w.prepared_by ? 'Waiting for preparer sign-off.' : open ? `${open} review note(s) must be cleared first.` : w.prepared_by === me ? 'A different person must review (segregation of duties).' : 'Ready for review.'}</p>
       ${isMgmt() && w.prepared_by && !open && w.prepared_by !== me ? '<button class="btn" data-signoff="review">Sign off as reviewer</button>' : ''}</div>`;
  return `<div class="crumb"><button class="link" data-backwp>&larr; Workpapers</button></div>
    <div class="card"><div class="toolbar"><h2>${esc(w.ref)} &middot; ${esc(w.title)}</h2>${badge(w.status)}${resultBadge(w.result)}
      <button class="btn ghost" data-edit="workpapers" data-id="${w.id}">Edit</button>
      ${['Ineffective', 'Partially effective'].includes(w.result) ? `<button class="btn ghost" data-raise="${w.id}">Raise issue</button>` : ''}
      ${!w.reviewed_by || isMgmt() ? `<button class="link" data-del="workpapers" data-id="${w.id}">Delete</button>` : ''}</div>
      ${signed ? '<p class="muted" style="margin-top:0">Editing the content of a signed-off workpaper removes its sign-offs.</p>' : ''}
      <div class="signoff">${prep}${rev}</div>
      ${signed && (isMgmt() || (w.prepared_by === me && !w.reviewed_by)) ? '<p><button class="link" data-signoff="remove">Remove sign-offs</button></p>' : ''}</div>
    <div class="card"><h2>Control &amp; test</h2>${kv([['Risk area', (byId('risks', w.risk_id) || {}).area], ['Framework reference', w.framework_ref], ['Control description', w.control_desc],
      ['Nature / frequency', [w.nature, w.frequency, w.key_control === 'Yes' && 'Key control'].filter(Boolean).join(' · ')], ['Test method', w.test_type], ['Procedure', w.procedure],
      ['Population', w.population], ['Sample size', w.sample_size], ['Exceptions', w.exceptions], ['Assigned to', uname(w.assigned_to)], ['Due', w.due_date], ['Results / notes', w.notes]])}</div>
    ${testEvidence(w)}
    ${testingTools(w)}
    <div class="card"><div class="toolbar"><h2>Review notes</h2><button class="btn" data-addnote="${w.id}">Add review note</button></div>
      ${N.length ? N.map(n => `<div class="note ${n.status}"><div>${badge(n.status)} <b>${esc(uname(n.created_by))}</b> <span class="muted">${esc(fmtTs(n.created_at))}</span></div>
        <p style="white-space:pre-wrap;margin:6px 0">${esc(n.note)}</p>
        ${n.response ? `<div class="muted">Response from ${esc(uname(n.responded_by))} (${esc(fmtTs(n.responded_at))}):</div><p style="white-space:pre-wrap;margin:4px 0">${esc(n.response)}</p>` : ''}
        <div>${n.status !== 'Cleared' ? `<button class="link" data-respond="${n.id}">Respond</button>` : ''}
        ${isMgmt() || n.created_by === me ? (n.status === 'Cleared' ? `<button class="link" data-noteact="reopen" data-id="${n.id}">Reopen</button>` : `<button class="link" data-noteact="clear" data-id="${n.id}">Clear</button>`) : ''}</div></div>`).join('') : '<div class="empty">No review notes.</div>'}</div>
    <div class="card"><h2>Issues raised</h2>${issueTable(inEng('issues').filter(i => i.workpaper_id === w.id))}</div>
    <div class="card"><div class="toolbar"><h2>History</h2><button class="btn ghost" data-loadlog="rec:${w.id}">Show history</button></div><div id="logBox"></div></div>`;
}

const MAX_MB = 50;
const wpFiles = wpId => S.files.filter(f => (byId('evidence', f.evidence_id) || {}).workpaper_id === wpId);

// Evidence panel shown inside a test: drop zone plus every file supporting it.
function testEvidence(w){
  const E = inEng('evidence').filter(x => x.workpaper_id === w.id);
  const rows = E.flatMap(x => { const F = S.files.filter(f => f.evidence_id === x.id); return F.length ? F.map(f => ({id:f.id, x, f})) : [{id:x.id, x}]; });
  const n = wpFiles(w.id).length, signed = w.prepared_by || w.reviewed_by;
  return `<div class="card" data-drop="${w.id}"><div class="toolbar"><h2>Test evidence &middot; ${n} file${n === 1 ? '' : 's'}</h2>
      <button class="btn ghost" data-addev="${w.id}" title="Track a request for evidence you have not received yet">New PBC request</button></div>
    <div class="fields">
      <div><label for="att_purpose">What is this file?</label><select id="att_purpose">${PURPOSES.map(p => `<option${p === S.att.purpose ? ' selected' : ''}>${esc(p)}</option>`).join('')}</select></div>
      <div><label for="att_desc">Description (optional)</label><input id="att_desc" value="${esc(S.att.desc)}" placeholder="e.g. AD user extraction as at 30 Sep 2026, 1,204 accounts"></div></div>
    <div class="dropzone"><div><b>Drag &amp; drop files here</b> or <label class="btn attach">Choose files<input type="file" multiple hidden data-attach="${w.id}"></label></div>
      <div class="muted" style="margin-top:6px">Up to ${MAX_MB} MB per file. Each file is fingerprinted (SHA-256) and the upload is logged. Text in screenshots and PDFs is read automatically.</div>
      ${signed ? '<div class="over" style="margin-top:6px">This test is signed off. Attaching or removing evidence removes the sign-offs so it can be re-reviewed.</div>' : ''}
      <div id="upProg"></div></div>
    ${rows.length ? table([
      ['File', r => r.f ? `<button class="link" data-file="${r.f.id}" data-name="${esc(r.f.name)}">${esc(r.f.name)}</button><div class="muted">${fmtSize(r.f.size)}</div>${ocrChip(r.f)}`
        : `${badge(r.x.pbc_status || 'No file')} <label class="link attach">Upload<input type="file" multiple hidden data-upload="${r.x.id}"></label>`],
      ['Purpose', r => r.x.purpose ? badge(r.x.purpose) : ''],
      ['Description', r => (!r.f || r.x.title !== r.f.name ? `<b>${esc(r.x.title)}</b>` : '') + (r.x.notes ? `<div class="muted">${esc(r.x.notes)}</div>` : '')],
      ['Uploaded', r => r.f ? `${esc(uname(r.f.created_by))}<div class="muted">${esc(fmtTs(r.f.created_at))}</div>` : `<span class="muted">${esc(r.x.requested_from || '')}</span>`],
      ['SHA-256', r => r.f ? `<span class="mono muted" title="${esc(r.f.sha256)}">${esc(r.f.sha256.slice(0, 16))}&hellip;</span>` : '']], rows,
      {actions:r => `<button class="link" data-edit="evidence" data-id="${r.x.id}">Edit</button>` +
        (r.f ? (isMgmt() || r.f.created_by === S.me.id ? `<button class="link" data-delfile="${r.f.id}">Remove</button>` : '') : `<button class="link" data-del="evidence" data-id="${r.x.id}">Delete</button>`)})
    : '<div class="empty">No evidence attached yet. Attach the extraction you tested, your sample selection and your test results here.</div>'}</div>`;
}

// Upload with progress (XHR, because fetch has no upload progress).
function upload(path, file, extra, onProgress){
  return new Promise((res, rej) => {
    const x = new XMLHttpRequest(); x.open('POST', '/api/' + path);
    x.setRequestHeader('X-Requested-With', 'fetch'); x.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    x.setRequestHeader('X-Filename', encodeURIComponent(file.name));
    for (const [k, v] of Object.entries(extra || {})) if (v) x.setRequestHeader(k, encodeURIComponent(v));
    x.upload.onprogress = e => onProgress && e.lengthComputable && onProgress(e.loaded / e.total);
    x.onload = () => { let d = {}; try { d = JSON.parse(x.responseText); } catch {} x.status < 300 ? res(d) : rej(new Error(d.error || `Upload failed (${x.status})`)); };
    x.onerror = () => rej(new Error(`Upload of ${file.name} failed. Check your connection and the ${MAX_MB} MB limit.`));
    x.send(file);
  });
}
async function attachFiles(wpId, files){
  if (!files.length) return;
  const bad = files.find(f => !f.size || f.size > MAX_MB * 1048576);
  if (bad) throw new Error(`${bad.name} ${bad.size ? `is larger than ${MAX_MB} MB` : 'is empty'}.`);
  const w = byId('workpapers', wpId);
  if (w && (w.prepared_by || w.reviewed_by) && !confirm('This test is signed off. Attaching evidence removes the sign-offs so it can be re-reviewed. Continue?')) return;
  S.busy++;
  try {
    for (const [i, f] of files.entries()){
      await upload(`workpapers/${wpId}/attach`, f, {'X-Purpose':S.att.purpose, 'X-Description':S.att.desc}, p => {
        const el = $('#upProg'); if (el) el.innerHTML = `<div class="muted">Uploading ${esc(f.name)} (${i + 1} of ${files.length})</div><div class="bar"><span style="width:${Math.round(p * 100)}%;background:var(--accent)"></span></div>`;
      });
    }
  } finally { S.busy--; }
  S.att.desc = '';
  toast(`${files.length} file${files.length > 1 ? 's' : ''} attached to ${w ? w.ref : 'the test'}`);
  await refresh();
}

/* ---------- OCR ---------- */
const OCR_BUSY = ['queued', 'running'];
const ocrConf = f => f.ocr_confidence != null && f.ocr_confidence !== '' ? Math.round(+f.ocr_confidence) : null;
function ocrChip(f){
  const doc = f.kind === 'pdf';
  if (OCR_BUSY.includes(f.ocr_status)) return `<div><span class="badge ocr-busy">Reading text&hellip;</span></div>`;
  if (f.ocr_status === 'done'){
    const c = ocrConf(f), pages = doc && f.pages ? `${f.pages} page${+f.pages === 1 ? '' : 's'}` : '';
    const label = !f.ocr_text ? 'no text found' : f.ocr_method === 'PDF text' ? 'text layer' : c != null ? `${c}% confidence` : '';
    return `<div><button class="link" data-ocr="${f.id}">View ${doc ? 'document' : 'image'} &amp; text</button>
      ${pages ? `<span class="muted">${pages}</span>` : ''} ${label ? `<span class="badge ${c != null && c < 75 ? 'b-Medium' : ''}" title="${esc(f.ocr_method || '')}">${label}</span>` : ''}</div>`;
  }
  if (f.ocr_status === 'failed') return `<div><button class="link" data-ocr="${f.id}">Reading failed &ndash; details</button></div>`;
  if (f.ocr_status === 'unavailable') return `<div class="muted" title="Ask your administrator to install the ${doc ? 'PDF tools (Poppler)' : 'OCR engine (Tesseract)'}">${doc ? 'PDF reading' : 'OCR'} not installed</div>`;
  return '';
}
// Page number of a character offset in extracted PDF text (pages are marked "--- Page n ---").
function pageAt(text, index){
  let page = null; const re = /^--- Page (\d+) ---$/gm; let m;
  while ((m = re.exec(text)) && m.index <= index) page = +m[1];
  return page;
}
// While any screenshot is being read, check back every few seconds (but never while someone is typing).
function scheduleOcrPoll(){
  clearTimeout(S.poll);
  if (!isStaff() || !S.files.some(f => OCR_BUSY.includes(f.ocr_status))) return;
  S.poll = setTimeout(function tick(){
    const a = document.activeElement;
    if (S.busy || (a && $('#view')?.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName))) S.poll = setTimeout(tick, 3000);
    else run(refresh);
  }, 3000);
}
function openOcr(fid){
  const f = byId('files', fid); if (!f) return;
  const doc = f.kind === 'pdf', pages = +f.pages || 1;
  S.ocrFile = fid; S.ocrPage = 1; S.ocrSel = '';
  const ev = byId('evidence', f.evidence_id) || {}, w = byId('workpapers', ev.workpaper_id), c = ocrConf(f);
  const text = f.ocr_status === 'done' ? f.ocr_text || '' : '';
  const lowConf = c != null && c < 75 && text;
  dlg.innerHTML = `<form><div class="toolbar"><h3 style="margin:0;flex:1;min-width:0;overflow-wrap:anywhere">${esc(f.name)}</h3>
      <button type="button" class="btn ghost" data-file="${f.id}" data-name="${esc(f.name)}">Download original</button>
      <button type="button" class="btn ghost" data-close>Close</button></div>
    <div class="ocr-grid">
      <div>${doc ? `<div class="toolbar pager"><button type="button" class="btn ghost" id="pgPrev" aria-label="Previous page">&lsaquo; Prev</button>
          <span id="pgNum" class="muted"></span><button type="button" class="btn ghost" id="pgNext" aria-label="Next page">Next &rsaquo;</button></div>` : ''}
        <div class="ocr-img" title="Click to toggle actual size"><img id="ocrImg" alt="${esc(f.name)}"></div></div>
      <div><div class="toolbar" style="margin-bottom:6px"><b style="flex:1">Text read from the ${doc ? 'document' : 'image'}</b>
          ${text ? badge(f.ocr_method === 'PDF text' ? 'exact text layer' : c != null ? c + '% confidence' : f.ocr_method || '', lowConf ? 'b-Medium' : '') : ''}</div>
        ${f.ocr_method && doc ? `<div class="muted" style="font-size:12px;margin-bottom:6px">${esc(f.ocr_method)}</div>` : ''}
        ${f.ocr_status === 'failed' ? `<p class="over">${esc(f.ocr_text)}</p>` : ''}
        ${lowConf ? '<p class="over" style="margin:0 0 6px">Low confidence: check every value against the original.</p>' : ''}
        <input id="ocrFind" type="search" placeholder="${doc ? 'Find in document, e.g. leavers' : 'Find in text, e.g. password length'}" aria-label="Find in text">
        <div id="ocrHits" class="muted" style="font-size:12px;min-height:1.2em"></div>
        <pre id="ocrText" class="ocr-text">${esc(text || (f.ocr_status === 'done' ? '(No text was found.)' : ''))}</pre>
        <div class="toolbar">${text ? '<button type="button" class="btn" id="ocrCopy">Copy text</button>' : ''}
          ${w && text ? `<button type="button" class="btn ghost" id="ocrAppend" title="${doc ? 'Select a passage first' : 'Adds the text, or just your selection'}">Add ${doc ? 'selected passage' : 'to test results'}${doc ? ` to ${esc(w.ref)}` : ` (${esc(w.ref)})`}</button>` : ''}
          ${S.ocr && (doc ? S.ocr.pdf : S.ocr.available) ? '<button type="button" class="btn ghost" id="ocrRerun">Read again</button>' : ''}</div>
        <p class="muted" style="font-size:12px">${f.ocr_method === 'PDF text' ? 'Text taken from the PDF itself' : `Read by ${esc(f.ocr_engine || 'OCR')}`}${f.ocr_at ? ' on ' + esc(fmtTs(f.ocr_at)) : ''}.
          The extracted text is a reading aid: verify key values against the original, which remains the evidence.</p></div></div></form>`;
  dlg.classList.add('wide');
  dlg.oncancel = null;
  dlg.querySelector('form').onsubmit = e => e.preventDefault();
  dlg.querySelector('.ocr-img').onclick = e => e.currentTarget.classList.toggle('actual');
  const show = n => {
    S.ocrPage = Math.min(Math.max(1, n), pages);
    $('#ocrImg').src = doc ? `/api/files/${f.id}/page/${S.ocrPage}` : `/api/files/${f.id}/view`;
    if (doc){ $('#pgNum').textContent = `Page ${S.ocrPage} of ${pages}`; $('#pgPrev').disabled = S.ocrPage === 1; $('#pgNext').disabled = S.ocrPage === pages; }
  };
  S.ocrShow = show; show(1);
  if (doc){ $('#pgPrev').onclick = () => show(S.ocrPage - 1); $('#pgNext').onclick = () => show(S.ocrPage + 1); }
  const selected = () => S.ocrSel;  // tracked on selectionchange: clicking a button clears the live selection
  const copy = $('#ocrCopy');
  if (copy) copy.onclick = async () => {
    const t = selected() || text;
    try { await navigator.clipboard.writeText(t); }
    catch { const r = document.createRange(); r.selectNodeContents($('#ocrText')); getSelection().removeAllRanges(); getSelection().addRange(r); document.execCommand('copy'); }
    toast(t === text ? 'Text copied' : 'Selection copied');
  };
  const add = $('#ocrAppend');
  if (add) add.onclick = () => run(async () => {
    const part = selected();
    if (doc && !part) throw new Error('Select the relevant passage in the text first (e.g. the clause on leavers).');
    const page = doc ? pageAt(text, text.indexOf(part)) : null;
    if ((w.prepared_by || w.reviewed_by) && !confirm(`${w.ref} is signed off. Changing its results removes the sign-offs. Continue?`)) return;
    const src = `${f.name}${page ? ', page ' + page : ''}`;
    const block = doc ? `[Extract from ${src}]\n${part}` : `[Text read by OCR from ${src} - verify against the image]\n${part || text}`;
    await api('PUT', 'workpapers/' + w.id, {notes:(w.notes ? w.notes + '\n\n' : '') + block, _version:w.updated_at});
    dlg.close(); toast(`Added to ${w.ref} results`); await refresh();
  });
  const again = $('#ocrRerun');
  if (again) again.onclick = () => run(async () => { await api('POST', `files/${f.id}/ocr`, {}); dlg.close(); toast('Reading again'); await refresh(); });
  dlg.showModal();
}
const reEscape = q => q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Wrap case-insensitive matches of q in <mark>, escaping everything else.
function markText(text, q){
  if (!q) return esc(text);
  return String(text).split(new RegExp(`(${reEscape(q)})`, 'ig')).map((part, i) => i % 2 ? `<mark>${esc(part)}</mark>` : esc(part)).join('');
}
function highlightOcr(q){
  const pre = $('#ocrText'), f = byId('files', S.ocrFile);
  if (!pre || !f || !f.ocr_text) return;
  q = q.trim();
  pre.innerHTML = markText(f.ocr_text, q);
  S.ocrSel = '';
  const n = q ? pre.querySelectorAll('mark').length : 0, hits = $('#ocrHits');
  if (f.kind === 'pdf' && n){  // list the pages with matches and show the first one
    const pages = [...new Set([...f.ocr_text.matchAll(new RegExp(reEscape(q), 'ig'))].map(m => pageAt(f.ocr_text, m.index)))];
    hits.textContent = `${n} match${n > 1 ? 'es' : ''} on page${pages.length > 1 ? 's' : ''} ${pages.join(', ')}`;
    if (S.ocrShow && pages[0]) S.ocrShow(pages[0]);
  } else hits.textContent = q ? `${n} match${n === 1 ? '' : 'es'}` : '';
  pre.querySelector('mark')?.scrollIntoView({block:'center'});
}
function showSearch(){
  const box = $('#evResults'); if (!box) return;
  const q = (S.q || '').trim(), ql = q.toLowerCase();
  if (q.length < 2){ box.innerHTML = ''; return; }
  const snippet = (t, i) => { const a = Math.max(0, i - 70), b = Math.min(t.length, i + q.length + 70);
    return (a ? '&hellip;' : '') + markText(t.slice(a, b), q) + (b < t.length ? '&hellip;' : ''); };
  const hits = [];
  for (const f of inEng('files')){
    const ev = byId('evidence', f.evidence_id) || {};
    const fields = [['Text in file', f.ocr_text], ['File name', f.name], ['Description', [ev.title, ev.purpose, ev.notes].filter(Boolean).join(' · ')]];
    const m = fields.find(([, t]) => t && t.toLowerCase().includes(ql));
    if (m){ const i = m[1].toLowerCase().indexOf(ql), page = m[0] === 'Text in file' && f.kind === 'pdf' ? pageAt(m[1], i) : null;
      hits.push({id:f.id, f, ev, where:m[0] + (page ? `, page ${page}` : ''), snip:snippet(m[1], i)}); }
  }
  box.innerHTML = hits.length ? table([
    ['File', h => h.f.ocr_status === 'done' ? `<button class="link" data-ocr="${h.f.id}">${esc(h.f.name)}</button>` : `<button class="link" data-file="${h.f.id}" data-name="${esc(h.f.name)}">${esc(h.f.name)}</button>`],
    ['Test', h => { const w = byId('workpapers', h.ev.workpaper_id); return w ? `<button class="link" data-open="wp" data-id="${w.id}">${esc(w.ref)}</button>` : ''; }],
    ['Found in', h => esc(h.where)], ['Match', h => `<span style="white-space:pre-wrap">${h.snip}</span>`]], hits)
    : `<div class="empty">No evidence matches &ldquo;${esc(q)}&rdquo;.</div>`;
}
function ocrAdminCard(){
  const o = S.ocr || {};
  const ok = (on, label, fix) => `<li>${on ? '&#10003;' : '<span class="over">&#10007;</span>'} ${label}${on ? '' : ` <span class="muted">&ndash; ${fix}</span>`}</li>`;
  return `<div class="card"><h2>Reading screenshots &amp; PDFs</h2><ul style="margin:0;padding-left:18px;list-style:none">
    ${ok(o.available, `Screenshot OCR${o.engine ? ` (${esc(o.engine)}, language ${esc(o.lang)})` : ''}`, 'install Tesseract: <code>sudo apt install tesseract-ocr</code> &middot; <code>brew install tesseract</code> &middot; Windows: UB Mannheim installer')}
    ${ok(o.enhanced, 'Screenshot enhancement for small text', 'install Pillow: <code>pip install pillow</code>')}
    ${ok(o.pdf, 'PDF text extraction and page previews', 'install Poppler: <code>sudo apt install poppler-utils</code> &middot; <code>brew install poppler</code> &middot; Windows: poppler for Windows, then set <code>AUDIT_POPPLER_DIR</code>')}
    ${ok(o.pdf && o.available, 'OCR of scanned PDF pages', 'needs both Poppler and Tesseract')}</ul>
    <p class="muted">Evidence is read on this server; nothing is sent outside your network. Restart Audit Workbench after installing a tool.</p></div>`;
}

/* ---------- Testing tools ---------- */
const OP_WORDS = {'>=':'at least', '<=':'at most', '=':'equal to', '!=':'not equal to'};
const RESULT_CLS = {'Pass':'b-Low', 'Exception':'b-Critical', 'Not found':'b-Medium'};
const isTabular = f => !f.kind && /\.(csv|tsv|txt|xlsx)$/i.test(f.name);
const wpTabular = wpId => wpFiles(wpId).filter(isTabular);
const shortHash = h => h ? `<span class="mono" title="SHA-256 ${esc(h)}">${esc(h.slice(0, 12))}&hellip;</span>` : '';
const J = v => { try { return JSON.parse(v || 'null'); } catch { return null; } };

function testingTools(w){
  const samples = S.samples.filter(x => x.workpaper_id === w.id).sort((a, b) => b.created_at.localeCompare(a.created_at));
  const runs = S.analyses.filter(x => x.workpaper_id === w.id).sort((a, b) => b.created_at.localeCompare(a.created_at));
  const checks = S.setting_checks.filter(x => x.workpaper_id === w.id);
  const fileLink = id => { const f = byId('files', id); return f ? `<button class="link" data-file="${f.id}" data-name="${esc(f.name)}">${esc(f.name)}</button>` : ''; };
  const req = r => `${OP_WORDS[r.operator] || r.operator} <b>${esc(r.expected)}</b>${r.unit ? ' ' + esc(r.unit) : ''}`;
  return `<div class="card"><h2>Testing tools</h2>
    <section class="tool"><div class="toolbar"><h3>Random sample selection</h3><button class="btn" data-sample="${w.id}">Draw random sample</button></div>
      <p class="muted">Draws a reproducible random sample from a population extraction attached to this test. The seed and the population's fingerprint are recorded so anyone can re-perform the selection.</p>
      ${samples.length ? table([['Drawn', x => `${esc(uname(x.created_by))}<div class="muted">${esc(fmtTs(x.created_at))}</div>`],
        ['Population', x => `${esc(x.population_name)}${x.sheet ? ` <span class="muted">(${esc(x.sheet)})</span>` : ''}<div class="muted">${esc(x.population_rows)} rows &middot; ${shortHash(x.population_sha256)}</div>`],
        ['Sample', x => `<b>${esc(x.size)}</b> items<div class="muted">seed ${esc(x.seed)}</div>`], ['Sample file', x => fileLink(x.sample_file_id)],
        ['Re-performance', x => x.verify_result ? `${badge(x.verify_result.startsWith('Verified') ? 'Verified' : 'Failed', x.verify_result.startsWith('Verified') ? 'b-Low' : 'b-Critical')}<div class="muted">${esc(uname(x.verified_by))}, ${esc(fmtTs(x.verified_at))}</div>` : '<span class="muted">not yet</span>']],
        samples, {actions:x => `<button class="link" data-verify="${x.id}">Re-perform</button>`}) : ''}</section>
    <section class="tool"><div class="toolbar"><h3>Access test: leavers &amp; dormant accounts</h3><button class="btn" data-access="${w.id}">Run access test</button></div>
      <p class="muted">Compares an account extraction (e.g. Active Directory) with the HR leavers report. It flags leavers still enabled, logons after termination, late disabling, dormant accounts and generic or shared accounts.</p>
      ${runs.length ? table([['Run', x => `${esc(uname(x.created_by))}<div class="muted">${esc(fmtTs(x.created_at))}</div>`],
        ['Inputs', x => (J(x.inputs) || []).map(i => `<div>${esc(i.role)}: ${esc(i.name)} <span class="muted">(${i.rows} rows)</span></div>`).join('')],
        ['As at', x => esc((J(x.summary) || {}).as_at)],
        ['Results', x => Object.entries(J(x.counts) || {}).filter(([, v]) => v).map(([k, v]) => `<div><b class="over">${v}</b> ${esc(k.toLowerCase())}</div>`).join('') || badge('No exceptions', 'b-Low')],
        ['Exceptions file', x => fileLink(x.result_file_id)]], runs,
        {actions:x => `<button class="link" data-analysis="${x.id}">View results</button>`}) : ''}</section>
    <section class="tool"><div class="toolbar"><h3>Policy vs actual settings</h3>
        <button class="btn ghost" data-suggest="${w.id}">Suggest from policy</button><button class="btn ghost" data-addcheck="${w.id}">Add check</button>
        <button class="btn" data-runchecks="${w.id}"${checks.length ? '' : ' disabled'}>Run checks</button></div>
      <p class="muted">Reads required values from policy documents in this engagement and compares them with the settings shown in this test's screenshots and documents. Each result shows the exact line it was read from.</p>
      ${checks.length ? table([['Setting', r => `<b>${esc(r.label)}</b>${r.match_text && r.match_text !== r.label ? `<div class="muted">looks for &ldquo;${esc(r.match_text)}&rdquo;</div>` : ''}`],
        ['Required', r => req(r) + (r.policy_ref ? `<div class="muted clamp" title="${esc(r.policy_ref)}">${esc(r.policy_ref)}</div>` : '')],
        ['Actual', r => r.check_actual != null ? `<b>${esc(r.check_actual)}</b>${r.unit ? ' ' + esc(r.unit) : ''}${r.check_source_file_id ? `<div class="muted">${fileLink(r.check_source_file_id)}</div><div class="mono muted">${esc(r.check_source_line)}</div>` : ''}` : ''],
        ['Result', r => r.check_result ? badge(r.check_result, RESULT_CLS[r.check_result]) + (r.check_note ? `<div class="muted" style="max-width:220px">${esc(r.check_note)}</div>` : '') : '<span class="muted">not run</span>']],
        checks, {actions:r => (r.check_result === 'Exception' ? `<button class="link" data-raisecheck="${r.id}">Raise issue</button>` : '') + editDel('setting_checks', r)})
        : '<div class="empty">No checks yet. Attach the policy (PDF) and the settings screenshot, then use <b>Suggest from policy</b>.</div>'}</section></div>`;
}

async function preview(fid, sheet){ return api('GET', `files/${fid}/table${sheet ? '?sheet=' + encodeURIComponent(sheet) : ''}`); }
const previewTable = p => `<div class="muted" style="margin:6px 0">${p.row_count.toLocaleString()} data rows${p.sheet ? ` in sheet &ldquo;${esc(p.sheet)}&rdquo;` : ''}. First rows:</div>
  <div class="tablewrap preview"><table><tr>${p.headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr>${p.rows.slice(0, 4).map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</table></div>`;
const fileOptions = (files, sel) => files.map(f => `<option value="${f.id}"${f.id === sel ? ' selected' : ''}>${esc(f.name)}</option>`).join('');
const needTabular = w => { toast(`Attach the extraction to ${w.ref} first (CSV or .xlsx), using the Test evidence panel.`, true); };

function sampleDialog(w){
  const files = wpTabular(w.id);
  if (!files.length) return needTabular(w);
  const pick = files.find(f => /population/i.test((byId('evidence', f.evidence_id) || {}).purpose || '')) || files[0];
  const form = modal(`Draw a random sample for ${w.ref}`, `<div class="fields">
      <div><label for="sp_file">Population file</label><select id="sp_file" name="file_id">${fileOptions(files, pick.id)}</select></div>
      <div><label for="sp_sheet">Sheet</label><select id="sp_sheet" name="sheet" disabled></select></div>
      <div class="wide" id="sp_prev"><span class="muted">Reading file&hellip;</span></div>
      <div><label for="sp_size">Sample size</label><input id="sp_size" name="size" type="number" min="1" required value="${esc(w.sample_size || suggestedSample(w.frequency, w.key_control === 'Yes') || '')}">
        <div class="hint">${w.frequency ? `Guide for this control (${esc(w.frequency.toLowerCase())}): ${esc(String(suggestedSample(w.frequency, false)))}&ndash;${esc(String(suggestedSample(w.frequency, true)))}` : 'Set the control frequency on the test to get a suggestion.'}</div></div>
      <div><label for="sp_seed">Seed (optional)</label><input id="sp_seed" name="seed" placeholder="leave blank to generate" pattern="[A-Za-z0-9_\\-]{1,40}">
        <div class="hint">Recorded with the sample. The same seed and population always give the same selection.</div></div></div>`,
    async f => {
      const d = Object.fromEntries(new FormData(f));
      const sm = await api('POST', `workpapers/${w.id}/sample`, {file_id:d.file_id, sheet:$('#sp_sheet').value || null, size:+d.size, seed:d.seed});
      toast(`Sample of ${sm.size} drawn (seed ${sm.seed}) and attached to ${w.ref}`); await refresh();
    }, {ok:'Draw sample'});
  const load = async sheet => {
    try {
      const p = await preview($('#sp_file').value, sheet);
      const sh = $('#sp_sheet'); sh.disabled = !p.sheets; sh.innerHTML = (p.sheets || []).map(n => `<option${n === p.sheet ? ' selected' : ''}>${esc(n)}</option>`).join('');
      $('#sp_prev').innerHTML = previewTable(p); $('#sp_size').max = p.row_count;
    } catch (e) { $('#sp_prev').innerHTML = `<p class="over">${esc(e.message)}</p>`; }
  };
  form.querySelector('#sp_file').onchange = () => load(); form.querySelector('#sp_sheet').onchange = e => load(e.target.value); load();
}
function verifyDialog(v){
  modal(v.verify_result === 'Verified' ? 'Sample re-performed: verified' : 'Sample re-performance failed', `
    <p>${badge(v.verify_result.startsWith('Verified') ? 'Verified' : 'Failed', v.verify_result.startsWith('Verified') ? 'b-Low' : 'b-Critical')} Sample of ${esc(v.size)} from ${esc(v.population_name)}, seed ${esc(v.seed)}.</p>
    ${table([['Check', c => esc(c[0])], ['Result', c => c[1] ? badge('OK', 'b-Low') : badge('Failed', 'b-Critical')], ['Detail', c => `<span class="mono">${esc(c[2])}</span>`]], v.checks.map((c, i) => Object.assign(c, {id:i})))}
    <p class="muted" style="font-size:12px">Method: ${esc(v.method)}</p>`, async () => {}, {ok:'Close', info:true});
}

const ROLE_LABELS = {user_key:'Account name *', user_enabled:'Enabled / status', user_last_logon:'Last logon date', user_disabled_on:'Date disabled (optional)',
  user_name:'Display name (optional)', leaver_key:'Account name / network ID *', leaver_term_date:'Termination date *'};
function accessDialog(w){
  const files = wpTabular(w.id);
  if (files.length < 2) return toast(`Attach both the account extraction and the HR leavers report to ${w.ref} first (CSV or .xlsx).`, true);
  const guessFile = re => (files.find(f => re.test(f.name)) || {}).id;
  const uDef = guessFile(/ad|user|account|entra|iam/i) || files[0].id, lDef = guessFile(/leaver|hr|termin|starter/i) || files.find(f => f.id !== uDef).id;
  const P = {};
  const side = (k, label, def, roles) => `<fieldset class="side"><legend>${label}</legend>
    <div class="fields"><div><label for="${k}_file">File</label><select id="${k}_file">${fileOptions(files, def)}</select></div>
      <div><label for="${k}_sheet">Sheet</label><select id="${k}_sheet" disabled></select></div>
      ${roles.map(r => `<div><label for="m_${r}">${ROLE_LABELS[r]}</label><select id="m_${r}" name="${r}"></select></div>`).join('')}
      ${k === 'u' ? `<div><label for="m_enabled_means">The status column shows</label><select id="m_enabled_means" name="enabled_means"><option value="enabled">Enabled = True/Yes</option><option value="disabled">Disabled = True/Yes</option></select></div>` : ''}</div>
    <div id="${k}_prev" class="muted">Reading file&hellip;</div></fieldset>`;
  const form = modal(`Access test for ${w.ref}: leavers & dormant accounts`,
    side('u', 'Account extraction', uDef, ['user_key', 'user_enabled', 'user_last_logon', 'user_disabled_on', 'user_name']) +
    side('l', 'HR leavers report', lDef, ['leaver_key', 'leaver_term_date']) +
    `<div class="fields" style="margin-top:12px">
      <div><label for="t_asat">Extraction date (as at) *</label><input id="t_asat" name="as_at" type="date" required value="${today()}"><div class="hint">The date the account list was run.</div></div>
      <div><label for="t_sla">Leaver SLA (days)</label><input id="t_sla" name="sla_days" type="number" min="0" value="1"><div class="hint">From your access policy.</div></div>
      <div><label for="t_dorm">Dormant after (days)</label><input id="t_dorm" name="dormant_days" type="number" min="1" value="90"></div>
      <div><label for="t_fmt">Date format in the files</label><select id="t_fmt" name="date_format"><option value="auto">Detect automatically</option>
        <option>DD/MM/YYYY</option><option>MM/DD/YYYY</option><option>YYYY-MM-DD</option></select></div></div>`,
    async f => {
      const d = Object.fromEntries(new FormData(f)), mapping = {};
      for (const r of Object.keys(ROLE_LABELS)) if (d[r]) mapping[r] = d[r];
      mapping.enabled_means = d.enabled_means; mapping.date_format = d.date_format;
      const a = await api('POST', `workpapers/${w.id}/access_test`, {users:{file_id:$('#u_file').value, sheet:$('#u_sheet').value || null},
        leavers:{file_id:$('#l_file').value, sheet:$('#l_sheet').value || null}, mapping, as_at:d.as_at, sla_days:+d.sla_days, dormant_days:+d.dormant_days});
      await refresh(); setTimeout(() => analysisDialog(byId('analyses', a.id)), 0);
    }, {ok:'Run test'});
  dlg.classList.add('wide');
  const load = async (k, sheet) => {
    try {
      const p = P[k] = await preview($(`#${k}_file`).value, sheet);
      const sh = $(`#${k}_sheet`); sh.disabled = !p.sheets; sh.innerHTML = (p.sheets || []).map(n => `<option${n === p.sheet ? ' selected' : ''}>${esc(n)}</option>`).join('');
      for (const r of Object.keys(ROLE_LABELS).filter(r => r.startsWith(k === 'u' ? 'user' : 'leaver'))){
        const required = ROLE_LABELS[r].endsWith('*');
        $(`#m_${r}`).innerHTML = (required ? '' : '<option value="">(not in this file)</option>') + p.headers.map(h => `<option${h === p.guess[r] ? ' selected' : ''}>${esc(h)}</option>`).join('');
      }
      $(`#${k}_prev`).innerHTML = previewTable(p);
    } catch (e) { $(`#${k}_prev`).innerHTML = `<p class="over">${esc(e.message)}</p>`; }
  };
  for (const k of ['u', 'l']){ form.querySelector(`#${k}_file`).onchange = () => load(k); form.querySelector(`#${k}_sheet`).onchange = e => load(k, e.target.value); load(k); }
}
function analysisDialog(a){
  if (!a) return;
  const sm = J(a.summary) || {}, counts = J(a.counts) || {}, exc = J(a.exceptions) || [], un = J(a.unmatched) || [], warn = J(a.warnings) || [];
  const total = +a.exceptions_count;
  dlg.classList.remove('wide');
  modal('Access test results', `<p class="muted" style="margin-top:0">As at ${esc(sm.as_at)} &middot; SLA ${esc(sm.sla_days)} day(s) &middot; dormant after ${esc(sm.dormant_days)} days &middot; run by ${esc(uname(a.created_by))}, ${esc(fmtTs(a.created_at))}</p>
    ${table([['Input', i => esc(i.role)], ['File', i => esc(i.name) + (i.sheet ? ` <span class="muted">(${esc(i.sheet)})</span>` : '')], ['Rows', i => i.rows], ['SHA-256', i => shortHash(i.sha256)]], (J(a.inputs) || []).map((i, n) => Object.assign(i, {id:n})))}
    <div class="grid" style="margin:12px 0">${stat(sm.accounts, 'Accounts')}${stat(sm.leavers_due, 'Leavers due by the as-at date')}${stat(sm.leavers_matched, 'Leavers matched to an account')}${stat(total, 'Exceptions', 1)}</div>
    <div class="legend" style="gap:8px;margin-bottom:8px">${Object.entries(counts).map(([k, v]) => `<span class="badge ${v ? 'b-Critical' : 'b-Low'}">${esc(k)}: ${v}</span>`).join('')}</div>
    ${warn.length ? `<div class="over" style="font-size:13px">${warn.map(esc).join('<br>')}</div>` : ''}
    ${exc.length ? `<label for="excFilter" class="muted" style="font-size:12px;font-weight:600">Show</label> <select id="excFilter" style="width:auto"><option value="">All exceptions (${exc.length})</option>
      ${Object.entries(counts).filter(([, v]) => v).map(([k, v]) => `<option>${esc(k)}</option>`).join('')}</select><div id="excTable"></div>` : '<p>No exceptions found.</p>'}
    ${un.length ? `<h3 style="font-size:14px">Leavers not found in the account list (${un.length})</h3><p class="muted" style="margin-top:0">The account may have been deleted, or the IDs differ between the two systems. Confirm manually.</p>
      ${table([['Leaver', u => esc(u.leaver)], ['Terminated', u => esc(u.termination_date)], ['Leavers row', u => u.row]], un.map((u, i) => Object.assign(u, {id:i})))}` : ''}
    <div class="toolbar" style="margin-top:12px">${total ? `<button type="button" class="btn ghost" data-raiseaccess="${a.id}">Raise issue</button>` : ''}
      <button type="button" class="btn ghost" data-file="${a.result_file_id}" data-name="${esc((byId('files', a.result_file_id) || {}).name || 'exceptions.csv')}">Download exceptions (CSV)</button></div>`,
    async () => {}, {ok:'Close', info:true});
  dlg.classList.add('wide');
  const draw = filter => { const box = $('#excTable'); if (!box) return;
    box.innerHTML = table([['Check', e => esc(e.check)], ['Account', e => `<b>${esc(e.account)}</b><div class="muted">${esc(e.name)}</div>`],
      ['Terminated', e => esc(e.termination_date)], ['Enabled', e => esc(e.enabled)], ['Last logon', e => esc(e.last_logon)], ['Detail', e => esc(e.detail)]],
      exc.filter(e => !filter || e.check === filter).map((e, i) => Object.assign(e, {id:i}))); };
  $('#excFilter')?.addEventListener('change', e => draw(e.target.value)); draw('');
}
async function suggestDialog(w){
  const props = await api('POST', `workpapers/${w.id}/setting_checks/suggest`, {});
  if (!props.length) return toast('No new requirements found. Attach the policy as a PDF to this engagement (text is read automatically), or add checks manually.', true);
  modal('Requirements found in policy documents', `<p class="muted" style="margin-top:0">Pick the requirements to check against this test's screenshots and documents. You can edit them afterwards.</p>
    ${table([['Setting', p => `<label><input type="checkbox" name="p" value="${p.i}" checked style="width:auto"> <b>${esc(p.label)}</b></label>`],
      ['Required', p => `${OP_WORDS[p.operator]} <b>${esc(p.expected)}</b> ${esc(p.unit || '')}`], ['From', p => `<span class="muted">${esc(p.policy_ref)}</span>`]],
      props.map((p, i) => Object.assign(p, {id:i, i})))}`,
    async f => {
      for (const i of new FormData(f).getAll('p')) await api('POST', 'setting_checks', {...props[i], id:undefined, i:undefined, engagement_id:w.engagement_id, workpaper_id:w.id});
      toast('Checks added. Press Run checks to compare them with the evidence.'); await refresh();
    }, {ok:'Add selected'});
}

/* ---------- Layout ---------- */
function render(){
  const app = $('#app');
  if (!S.me) return renderLogin(app);
  const secs = SECTIONS();
  if (!secs.some(s => s[0] === S.sec) && S.sec !== 'eng') S.sec = secs[0][0];
  const last = byId('engagements', S.eng), eng = S.sec === 'eng' && last;
  app.innerHTML = `<header><h1>Audit Workbench</h1>
      ${isStaff() ? `<select id="engSel" style="width:auto;min-width:200px" aria-label="Open engagement"><option value="">Open engagement...</option>
        ${S.engagements.map(e => `<option value="${e.id}"${e.id === S.eng && S.sec === 'eng' ? ' selected' : ''}>${esc(e.name)}</option>`).join('')}</select>` : ''}
      <span class="spacer"></span><span class="who">${esc(S.me.name)} &middot; ${esc(S.me.role)}</span>
      <button class="btn ghost" id="refreshBtn" title="Load the latest changes from your team">Refresh</button>
      <button class="btn ghost" id="pwBtn">Password</button><button class="btn ghost" id="logoutBtn">Sign out</button></header>
    <nav>${secs.map(([k, l]) => `<button data-sec="${k}" class="${S.sec === k ? 'active' : ''}">${l}</button>`).join('')}
      ${last ? `<button class="${eng ? 'active' : ''}" data-sec="eng">&#9656; ${esc(last.name)}</button>` : ''}</nav>
    ${eng ? `<nav class="sub">${ENG_TABS().map(([k, l]) => `<button data-tab="${k}" class="${S.tab === k && !S.wp ? 'active' : ''}">${l}</button>`).join('')}</nav>` : ''}
    <main id="view">${(eng || S.sec !== 'eng') ? V[eng ? 'eng' : S.sec]() : V.home()}</main>`;
  if (S.me.must_change) passwordDialog(true);
  scheduleOcrPoll();
  if (S.sec === 'eng' && S.tab === 'evidence' && !S.wp) showSearch();
}
function renderLogin(app){
  dlg.open && dlg.close();
  app.innerHTML = `<div class="card login"><h2>Audit Workbench</h2><form id="loginForm"><div class="fields">
    <div><label for="lu">Username</label><input id="lu" name="username" autocomplete="username" required></div>
    <div><label for="lp">Password</label><input id="lp" name="password" type="password" autocomplete="current-password" required></div></div>
    <div class="dlgbar"><button class="btn">Sign in</button></div><p id="loginErr" class="over"></p></form></div>`;
  $('#loginForm').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'login', Object.fromEntries(new FormData(e.target))); await refresh(); }
    catch (err) { $('#loginErr').textContent = err.message; }
  };
  $('#lu').focus();
}
function passwordDialog(forced){
  modal(forced ? 'Set a new password' : 'Change password', `${forced ? '<p class="muted">You must choose a new password before continuing.</p>' : ''}<div class="fields">
    <div class="wide"><label for="pw0">Current password</label><input id="pw0" name="old" type="password" autocomplete="current-password" required></div>
    <div class="wide"><label for="pw1">New password (min 10 characters)</label><input id="pw1" name="new" type="password" minlength="10" autocomplete="new-password" required></div>
    <div class="wide"><label for="pw2">Confirm new password</label><input id="pw2" name="confirm" type="password" minlength="10" autocomplete="new-password" required></div></div>`,
    async form => {
      const d = Object.fromEntries(new FormData(form));
      if (d.new !== d.confirm) throw new Error('New passwords do not match.');
      await api('POST', 'me/password', {old:d.old, new:d.new});
      S.me.must_change = false; toast('Password changed');
    }, {noCancel:forced, ok:'Change password'});
}

/* ---------- Events ---------- */
document.addEventListener('click', e => {
  if (e.target.closest('label.attach, input[type=file]')) return;  // let file pickers open without opening the row
  const el = e.target.closest('button, tr.click, [data-close]'); if (!el) return;
  const d = el.dataset;
  if ('close' in d) return dlg.close();
  if (el.id === 'logoutBtn') return run(async () => { await api('POST', 'logout'); S.me = null; render(); });
  if (el.id === 'pwBtn') return passwordDialog(false);
  if (el.id === 'refreshBtn') return run(async () => { await refresh(); toast('Up to date'); });
  if (el.id === 'printBtn') return print();
  if (el.id === 'libBtn') return openLibrary();
  if (d.sec){ S.sec = d.sec; S.wp = null; return render(); }
  if (d.tab){ S.tab = d.tab; S.wp = null; return render(); }
  if (d.open === 'eng'){ S.eng = d.id; S.sec = 'eng'; S.tab = 'overview'; S.wp = null; return render(); }
  if (d.open === 'wp' || d.open === 'wpnote'){
    const n = d.open === 'wpnote' ? byId('review_notes', d.id) : null, wpId = n ? n.workpaper_id : d.id, w = byId('workpapers', wpId);
    if (!w) return; S.eng = w.engagement_id; S.sec = 'eng'; S.tab = 'workpapers'; S.wp = wpId; render(); return scrollTo(0, 0);
  }
  if (d.open === 'issue'){ const i = byId('issues', d.id); S.eng = i.engagement_id; return openForm('issues', i); }
  if (d.open === 'myissue') return auditeeIssue(byId('issues', d.id));
  if (d.goeng){ S.eng = d.goeng; S.sec = 'eng'; S.tab = 'overview'; S.wp = null; return render(); }
  if (d.backwp !== undefined){ S.wp = null; return render(); }
  if (d.new) return openForm(d.new, null, defaultsFor(d.new), d.new === 'engagements' ? async saved => { S.eng = saved.id; S.sec = 'eng'; S.tab = 'planning'; } : null);
  if (d.edit) return openForm(d.edit, d.edit === 'users' ? S.users.find(u => u.id === d.id) : byId(d.edit, d.id));
  if (d.del) return run(async () => {
    const label = d.del === 'engagements' ? 'this engagement and ALL its workpapers, evidence, notes, issues and time' : 'this ' + (SCHEMAS[d.del].label || '').toLowerCase();
    if (!confirm(`Delete ${label}? This cannot be undone (it stays in the audit trail).`)) return;
    await api('DELETE', `${d.del}/${d.id}`);
    if (d.del === 'workpapers') S.wp = null;
    if (d.del === 'engagements'){ S.eng = null; S.sec = 'engs'; }
    toast('Deleted'); await refresh();
  });
  if (d.signoff) return run(async () => {
    if (d.signoff === 'remove' && !confirm('Remove the sign-offs on this workpaper?')) return;
    await api('POST', `workpapers/${S.wp}/signoff`, {kind:d.signoff}); toast('Sign-off updated'); await refresh();
  });
  if (d.addnote) return openForm('review_notes', null, {workpaper_id:d.addnote});
  if (d.respond) return modal('Respond to review note', `<p style="white-space:pre-wrap">${esc(byId('review_notes', d.respond).note)}</p>
    <div class="fields"><div class="wide"><label for="rsp">Response</label><textarea id="rsp" name="response" required></textarea></div></div>`,
    async form => { await api('POST', `review_notes/${d.respond}/respond`, Object.fromEntries(new FormData(form))); toast('Response saved'); await refresh(); });
  if (d.noteact) return run(async () => { await api('POST', `review_notes/${d.id}/${d.noteact}`, {}); await refresh(); });
  if (d.addev) return openForm('evidence', null, {workpaper_id:d.addev, pbc_status:'Requested', requested_on:today()});
  if (d.raise){ const w = byId('workpapers', d.raise);
    return openForm('issues', null, {workpaper_id:w.id, status:'Open', title:`${w.title} - control deficiency`, criteria:w.control_desc,
      condition:`Testing of ${w.ref} found ${w.exceptions || '?'} exception(s) in a sample of ${w.sample_size || '?'}.`}); }
  if (d.file) return run(async () => {
    const r = await fetch('/api/files/' + d.file, {credentials:'same-origin'});
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'Download failed');
    const a = document.createElement('a'); a.href = URL.createObjectURL(await r.blob()); a.download = d.name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  });
  if (d.delfile) return run(async () => { if (!confirm('Remove this file? The removal is logged.')) return; await api('DELETE', 'files/' + d.delfile); await refresh(); });
  if (d.toplan) return openForm('plan', null, {universe_id:d.toplan, title:'Audit of ' + byId('universe', d.toplan).name, year:S.year, status:'Planned'}, async () => { S.sec = 'plan'; });
  if (d.mkeng) return run(async () => {
    const p = byId('plan', d.mkeng), u = byId('universe', p.universe_id) || {};
    const e = await api('POST', 'engagements', {name:p.title, universe_id:p.universe_id, lead_id:p.lead_id, budget_hours:p.budget_hours, auditee:u.owner, status:'Planning'});
    await api('PUT', 'plan/' + p.id, {engagement_id:e.id, status:'In progress', _version:p.updated_at});
    await loadAll(); S.eng = e.id; S.sec = 'eng'; S.tab = 'planning'; render(); toast('Engagement created from plan');
  });
  if (d.csv) return exportCsv(d.csv);
  if (d.loadlog) return run(() => loadLog(d.loadlog));
  if (d.ocr) return openOcr(d.ocr);
  if (d.sample) return sampleDialog(byId('workpapers', d.sample));
  if (d.verify) return run(async () => { const v = await api('POST', `samples/${d.verify}/verify`, {}); await refresh(); verifyDialog(v); });
  if (d.access) return accessDialog(byId('workpapers', d.access));
  if (d.analysis) return analysisDialog(byId('analyses', d.analysis));
  if (d.suggest) return run(() => suggestDialog(byId('workpapers', d.suggest)));
  if (d.runchecks) return run(async () => {
    const rows = await api('POST', `workpapers/${d.runchecks}/setting_checks/run`, {});
    const n = k => rows.filter(r => r.check_result === k).length;
    toast(`${n('Pass')} pass, ${n('Exception')} exception${n('Exception') === 1 ? '' : 's'}, ${n('Not found')} not found`); await refresh();
  });
  if (d.addcheck) return openForm('setting_checks', null, {workpaper_id:d.addcheck, operator:'>='});
  if (d.raisecheck){ const r = byId('setting_checks', d.raisecheck), src = byId('files', r.check_source_file_id) || {};
    return openForm('issues', null, {workpaper_id:r.workpaper_id, status:'Open', title:`${r.label} does not meet policy`,
      condition:`${r.label} is set to ${r.check_actual}${r.unit ? ' ' + r.unit : ''} (source: ${src.name || 'evidence'}: "${r.check_source_line || ''}").`,
      criteria:`Requirement: ${r.label} ${OP_WORDS[r.operator]} ${r.expected}${r.unit ? ' ' + r.unit : ''}.${r.policy_ref ? ' ' + r.policy_ref : ''}`}); }
  if (d.raiseaccess){ const a = byId('analyses', d.raiseaccess), c = JSON.parse(a.counts), sm = JSON.parse(a.summary);
    return openForm('issues', null, {workpaper_id:a.workpaper_id, status:'Open', title:'Leaver and dormant account exceptions',
      condition:`Comparing the account list with the HR leavers report as at ${sm.as_at}: ` + Object.entries(c).filter(([, v]) => v).map(([k, v]) => `${v} × ${k.toLowerCase()}`).join('; ') +
        `. Details in the attached exceptions file.`,
      criteria:`Leavers' access must be disabled within ${sm.sla_days} day(s) of termination; inactive accounts should be reviewed and disabled.`}); }
});
document.addEventListener('change', e => {
  const t = e.target;
  if (t.id === 'engSel'){ if (t.value){ S.eng = t.value; S.sec = 'eng'; S.tab = 'overview'; S.wp = null; } render(); }
  else if (t.id === 'yearSel'){ S.year = t.value === '__next' ? String(Math.max(...[...t.options].map(o => +o.value || 0)) + 1) : t.value; render(); }
  else if (t.dataset.filt !== undefined){ S.filt[t.dataset.filt] = t.value; render(); }
  else if (t.id === 'att_purpose') S.att.purpose = t.value;
  else if (t.dataset.attach){ const files = [...t.files]; t.value = ''; run(() => attachFiles(t.dataset.attach, files)); }
  else if (t.dataset.upload) run(async () => {
    const files = [...t.files]; t.value = '';
    const bad = files.find(f => !f.size || f.size > MAX_MB * 1048576);
    if (bad) throw new Error(`${bad.name} ${bad.size ? `is larger than ${MAX_MB} MB` : 'is empty'}.`);
    for (const f of files) await upload(`evidence/${t.dataset.upload}/files`, f);
    toast('Uploaded'); await refresh();
  });
});
// Remember the last text selected in the OCR viewer; selections made elsewhere are ignored.
document.addEventListener('selectionchange', () => {
  const pre = $('#ocrText'), sel = getSelection();
  if (pre && sel.rangeCount && pre.contains(sel.anchorNode)) S.ocrSel = sel.toString().trim();
});
document.addEventListener('input', e => {
  if (e.target.id === 'att_desc') S.att.desc = e.target.value;
  else if (e.target.id === 'evSearch'){ S.q = e.target.value; showSearch(); }
  else if (e.target.id === 'ocrFind') highlightOcr(e.target.value);
});
window.addEventListener('focus', () => { if (S.me && !dlg.open && !S.busy) run(refresh); });
// Drag & drop onto a test's evidence panel; ignore drops elsewhere so the browser doesn't navigate away.
const dropZone = e => e.target.closest && e.target.closest('[data-drop]');
document.addEventListener('dragover', e => { e.preventDefault(); const z = dropZone(e); if (z) z.classList.add('over-drop'); });
document.addEventListener('dragleave', e => { const z = dropZone(e); if (z && !z.contains(e.relatedTarget)) z.classList.remove('over-drop'); });
document.addEventListener('drop', e => {
  e.preventDefault(); const z = dropZone(e); if (!z) return;
  z.classList.remove('over-drop'); run(() => attachFiles(z.dataset.drop, [...e.dataTransfer.files]));
});

function defaultsFor(t){
  return {workpapers:{status:'Not started', result:'Not concluded'}, evidence:{pbc_status:'Requested', requested_on:today()}, issues:{status:'Open'},
    time_entries:{date:today(), user_id:S.me.id}, plan:{year:S.year, status:'Planned'}, engagements:{status:'Planning', lead_id:S.me.id}, users:{role:'auditor'}}[t] || {};
}
function auditeeIssue(i){
  const e = byId('engagements', i.engagement_id) || {};
  modal(i.title, `<p>${critBadge(i)} <span class="muted">${esc(e.name)} &middot; due ${esc(i.due_date || '-')}</span></p>
    ${kv([['Condition', i.condition], ['Criteria', i.criteria], ['Cause', i.cause], ['Effect', i.effect], ['Recommendation', i.recommendation]])}
    <div class="fields" style="margin-top:12px"><div class="wide"><label for="ar">Management response / action plan</label><textarea id="ar" name="response">${esc(i.response)}</textarea></div>
    <div><label for="as">Status</label><select id="as" name="status">${[i.status, 'Remediation in progress', 'Ready for validation'].filter((v, n, a) => v && a.indexOf(v) === n)
      .map(s => `<option${s === i.status ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select></div></div>`,
    async form => { await api('PUT', 'issues/' + i.id, {...Object.fromEntries(new FormData(form)), _version:i.updated_at}); toast('Response saved'); await refresh(); });
}
function openLibrary(){
  const have = new Set(inEng('workpapers').map(w => w.ref));
  modal('ITGC control library', `<p class="muted">Pick standard IT general controls to add as workpapers. You can edit them afterwards.</p>
    <div class="tablewrap"><table>${LIBRARY.map((c, i) => `<tr><td><input type="checkbox" name="c" value="${i}" style="width:auto"${have.has(c[0]) ? ' disabled' : ''} aria-label="${esc(c[1])}"></td>
      <td><b>${c[0]}</b></td><td>${esc(c[1])}<div class="muted">${esc(c[3])}</div></td><td class="muted">${esc(c[4])}</td></tr>`).join('')}</table></div>`,
    async form => {
      for (const i of new FormData(form).getAll('c')){
        const [ref, title, area, control_desc, frequency, procedure] = LIBRARY[i];
        let risk = inEng('risks').find(r => r.area === area);
        if (!risk){ risk = await api('POST', 'risks', {engagement_id:S.eng, area}); S.risks.push(risk); }
        await api('POST', 'workpapers', {engagement_id:S.eng, ref, title, control_desc, frequency, procedure, risk_id:risk.id,
          key_control:'Yes', sample_size:String(suggestedSample(frequency, true)), test_type:'Inspection'});
      }
      toast('Added'); await refresh();
    }, {ok:'Add selected'});
}
async function loadLog(which){
  const q = which === 'all' ? '' : which.startsWith('rec:') ? 'record_id=' + which.slice(4) : 'engagement_id=' + which;
  const rows = await api('GET', 'audit_log?' + q);
  // Show names instead of internal IDs for user and record references.
  const label = (k, v) => { if (!v || !/_id$|_by$|^assigned_to$/.test(k)) return v;
    const u = S.users.find(x => x.id === v); if (u) return u.name;
    const ref = ['workpapers','risks','issues','universe','engagements','evidence'].map(t => byId(t, v)).find(Boolean);
    return ref ? ref.ref || ref.title || ref.name || ref.area : v; };
  const det = r => { if (!r.detail) return ''; const d = Object.fromEntries(Object.entries(JSON.parse(r.detail)).filter(([k]) => k !== 'engagement_id')
      .map(([k, v]) => [k, Array.isArray(v) ? v.map(x => label(k, x)) : label(k, v)]));
    return Object.entries(d).map(([k, v]) => Array.isArray(v) ? `${k}: ${String(v[0] ?? '').slice(0, 60)} &rarr; ${String(v[1] ?? '').slice(0, 60)}` : `${k}: ${String(v).slice(0, 80)}`).map(s => esc(s).replace(/&amp;rarr;/g, '&rarr;')).join('<br>'); };
  $('#logBox').innerHTML = table([['When', r => esc(fmtTs(r.ts))], ['Who', r => esc(r.user_name)], ['Action', r => esc(r.action.replace(/_/g, ' '))], ['Record', r => esc(r.table_name)], ['Detail', det]], rows, {empty:'No events.'});
}
function exportCsv(kind){
  const engN = id => (byId('engagements', id) || {}).name;
  const issueRow = i => ({Engagement:engN(i.engagement_id), Criticality:crit(i), Score:riskScore(i.likelihood, i.impact), Title:i.title, Workpaper:(byId('workpapers', i.workpaper_id) || {}).ref,
    Condition:i.condition, Criteria:i.criteria, Cause:i.cause, Effect:i.effect, Recommendation:i.recommendation, Owner:uname(i.owner_id), Due:i.due_date, Status:i.status, 'Management response':i.response});
  const rows = kind === 'issues' ? S.issues.map(issueRow) : kind === 'engissues' ? inEng('issues').map(issueRow)
    : inEng('workpapers').map(w => ({Ref:w.ref, Control:w.title, 'Framework ref':w.framework_ref, Risk:(byId('risks', w.risk_id) || {}).area, Method:w.test_type, Frequency:w.frequency,
      Population:w.population, Sample:w.sample_size, Exceptions:w.exceptions, 'Assigned to':uname(w.assigned_to), Status:w.status, Conclusion:w.result,
      'Prepared by':uname(w.prepared_by), 'Prepared at':w.prepared_at, 'Reviewed by':uname(w.reviewed_by), 'Reviewed at':w.reviewed_at}));
  if (!rows.length) return toast('Nothing to export.', true);
  const cell = v => { v = String(v ?? ''); if (/^[=+\-@]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
  const csv = [Object.keys(rows[0]), ...rows.map(Object.values)].map(r => r.map(cell).join(',')).join('\r\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['﻿' + csv], {type:'text/csv'})); a.download = `${kind}-${today()}.csv`; a.click();
}

api('GET', 'me').then(() => refresh()).catch(() => render());
