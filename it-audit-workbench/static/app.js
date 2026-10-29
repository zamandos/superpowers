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
    {k:'title',l:'Evidence / request',req:1},{k:'workpaper_id',l:'Supports workpaper',t:'ref',ref:'workpapers'},
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
const TABLES = ['universe','plan','engagements','risks','workpapers','evidence','files','review_notes','issues','time_entries'];

/* ---------- State & helpers ---------- */
const S = {me:null, users:[], sec:'home', tab:'overview', eng:null, wp:null, year:String(new Date().getFullYear()), filt:{}};
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
  if (f.t === 'user') return S.users.filter(u => u.active && (f.all || u.role !== 'auditee')).map(u => [u.id, u.name + (u.role === 'auditee' ? ' (auditee)' : '')]);
  const rows = f.ref === 'universe' ? S.universe : inEng(f.ref);
  return rows.map(r => [r.id, f.ref === 'workpapers' ? `${r.ref} - ${r.title}` : r.area || r.name]);
}
function fieldHtml(f, v, isNew){
  if ((f.newOnly && !isNew) || (f.editOnly && isNew) || (f.mgmt && !isMgmt())) return '';
  const id = 'f_' + f.k, req = f.req && !(f.t === 'password' && !isNew) ? ' required' : '';
  let inp;
  if (['select','user','ref'].includes(f.t)){
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
  dlg.innerHTML = `<form><h3>${esc(title)}</h3>${inner}<div id="calc" class="muted" style="margin-top:8px"></div>
    <div class="dlgbar">${opts.noCancel ? '' : '<button type="button" class="btn ghost" data-close>Cancel</button>'}<button class="btn" id="saveBtn">${esc(opts.ok || 'Save')}</button></div></form>`;
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
      `<div class="card"><div class="toolbar"><h2>Audit trail</h2><button class="btn ghost" data-loadlog="all">Load latest 500 events</button></div><div id="logBox" class="muted">Every create, edit, delete, sign-off, upload, download and sign-in is recorded.</div></div>`;
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
        ['Evidence', w => inEng('evidence').filter(x => x.workpaper_id === w.id).length], ['Notes', w => { const n = openNotes(w.id).length; return n ? `<span class="over">${n} open</span>` : ''; }],
        ['Due', w => due(w.due_date, w.status)], ['Status', w => badge(w.status)], ['Conclusion', w => resultBadge(w.result)],
        ['Prepared', w => so(w.prepared_by, w.prepared_at)], ['Reviewed', w => so(w.reviewed_by, w.reviewed_at)]], W, {open:'wp'})}</div>`;
  },
  evidence(){
    const E = inEng('evidence');
    return `<div class="card"><div class="toolbar"><h2>Evidence &amp; PBC requests</h2><button class="btn" data-new="evidence">New request / evidence</button></div>
      <p class="muted" style="margin-top:0">Files are stored on the server with a SHA-256 fingerprint so you can show they were not altered after collection. Every upload and download is logged.</p>
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
  return table([['Evidence', x => `<b>${esc(x.title)}</b><div class="muted">${esc(x.type)}</div>`],
    ['Workpaper', x => { const w = byId('workpapers', x.workpaper_id); return w ? esc(w.ref) : '<span class="muted">unlinked</span>'; }],
    ['Request', x => badge(x.pbc_status) + `<div class="muted">${esc(x.requested_from)}${x.requested_on ? ' &middot; ' + esc(x.requested_on) : ''}</div>`],
    ['Received', x => esc(x.collected_on) + (x.collected_by ? `<div class="muted">by ${esc(x.collected_by)}</div>` : '')],
    ['Files', x => S.files.filter(f => f.evidence_id === x.id).map(f => `<div><button class="link" data-file="${f.id}" data-name="${esc(f.name)}">${esc(f.name)}</button> <span class="muted">${fmtSize(f.size)}</span>
      ${isMgmt() || f.created_by === S.me.id ? `<button class="link" data-delfile="${f.id}" title="Remove file">&times;</button>` : ''}
      <div class="mono muted" title="SHA-256 fingerprint">SHA-256 ${esc(f.sha256)}</div></div>`).join('') + `<label class="link" style="cursor:pointer">+ Upload<input type="file" multiple hidden data-upload="${x.id}"></label>`]],
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
    <div class="card"><div class="toolbar"><h2>Review notes</h2><button class="btn" data-addnote="${w.id}">Add review note</button></div>
      ${N.length ? N.map(n => `<div class="note ${n.status}"><div>${badge(n.status)} <b>${esc(uname(n.created_by))}</b> <span class="muted">${esc(fmtTs(n.created_at))}</span></div>
        <p style="white-space:pre-wrap;margin:6px 0">${esc(n.note)}</p>
        ${n.response ? `<div class="muted">Response from ${esc(uname(n.responded_by))} (${esc(fmtTs(n.responded_at))}):</div><p style="white-space:pre-wrap;margin:4px 0">${esc(n.response)}</p>` : ''}
        <div>${n.status !== 'Cleared' ? `<button class="link" data-respond="${n.id}">Respond</button>` : ''}
        ${isMgmt() || n.created_by === me ? (n.status === 'Cleared' ? `<button class="link" data-noteact="reopen" data-id="${n.id}">Reopen</button>` : `<button class="link" data-noteact="clear" data-id="${n.id}">Clear</button>`) : ''}</div></div>`).join('') : '<div class="empty">No review notes.</div>'}</div>
    <div class="card"><div class="toolbar"><h2>Evidence</h2><button class="btn" data-addev="${w.id}">Add evidence</button></div>${evidenceTable(inEng('evidence').filter(x => x.workpaper_id === w.id))}</div>
    <div class="card"><h2>Issues raised</h2>${issueTable(inEng('issues').filter(i => i.workpaper_id === w.id))}</div>
    <div class="card"><div class="toolbar"><h2>History</h2><button class="btn ghost" data-loadlog="rec:${w.id}">Show history</button></div><div id="logBox"></div></div>`;
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
});
document.addEventListener('change', e => {
  const t = e.target;
  if (t.id === 'engSel'){ if (t.value){ S.eng = t.value; S.sec = 'eng'; S.tab = 'overview'; S.wp = null; } render(); }
  else if (t.id === 'yearSel'){ S.year = t.value === '__next' ? String(Math.max(...[...t.options].map(o => +o.value || 0)) + 1) : t.value; render(); }
  else if (t.dataset.filt !== undefined){ S.filt[t.dataset.filt] = t.value; render(); }
  else if (t.dataset.upload) run(async () => {
    for (const f of t.files) await api('POST', `evidence/${t.dataset.upload}/files`, undefined, f);
    toast('Uploaded'); await refresh();
  });
});
window.addEventListener('focus', () => { if (S.me && !dlg.open) run(refresh); });

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
