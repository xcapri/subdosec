(function(){
  // ── State ──────────────────────────────────────────────────────
  let data = {vulns:{},undetect:[],service_map:{},stats:{}};
  let activeTab = 'vulns';
  let searchQuery = '';
  
  let vulnSortCol = '';
  let vulnSortAsc = true;
  let undSortCol = '';
  let undSortAsc = true;

  let vulnPage = 1;
  let undPage = 1;
  const pageSize = 10;
  
  let refreshTimer;
  let countdown = 30;

  let selectedVulns = new Set();   // "service|||subdomain"
  let selectedUndetect = new Set(); // subdomain string
  let exportFormat = 'json';

  const vulnFields = [
    {key:'subdomain',label:'Subdomain',checked:true},
    {key:'service',label:'Service',checked:true},
  ];
  const undetectFields = [
    {key:'subdomain',label:'Subdomain',checked:true},
    {key:'rootdomain',label:'Root Domain',checked:true},
    {key:'potential',label:'Potential Status',checked:true},
    {key:'title',label:'Title',checked:true},
    {key:'status_code',label:'Status Code',checked:true},
    {key:'cname_records',label:'CNAME Records',checked:true},
    {key:'a_records',label:'A Records',checked:true},
    {key:'redirect_url',label:'Redirect URL',checked:true},
    {key:'reason',label:'Reason',checked:true},
  ];

  // ── DOM refs ───────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const vulnBody      = $('vulnBody');
  const undetectBody  = $('undetectBody');
  const searchInput   = $('searchInput');
  const clearBtn      = $('clearSearch');
  const selToolbar    = $('selToolbar');
  const selCount      = $('selCount');
  const vulnAllChk    = $('vulnAllChk');
  const undAllChk     = $('undAllChk');

  // ── Fetch ──────────────────────────────────────────────────────
  async function fetchData(){
    try{
      const r = await fetch('/api/data');
      data = await r.json();
      render();
      $('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    }catch(e){ console.error('Fetch failed',e); }
  }

  // ── Selection helpers ──────────────────────────────────────────
  function getActiveSelection(){ return activeTab==='vulns' ? selectedVulns : selectedUndetect; }
  function totalSelected(){ return getActiveSelection().size; }

  function updateToolbar(){
    const n = totalSelected();
    selCount.textContent = n;
    selToolbar.classList.toggle('show', n > 0);
    syncSelectAllChk();
  }

  function syncSelectAllChk(){
    const visible = getVisibleKeys();
    const sel = getActiveSelection();
    const chk = activeTab==='vulns' ? vulnAllChk : undAllChk;
    if(!visible.length){ chk.checked=false; chk.indeterminate=false; return; }
    const allSel = visible.every(k=>sel.has(k));
    const someSel = visible.some(k=>sel.has(k));
    chk.checked = allSel;
    chk.indeterminate = !allSel && someSel;
  }

  // Gets ALL currently visible key IDs (ignoring pagination, for Select All checkboxes)
  function getVisibleKeys(){
    if(activeTab==='vulns'){
      const q = searchQuery.toLowerCase();
      const list = getVulnsList();
      const filtered = q ? list.filter(i=>i.subdomain.toLowerCase().includes(q) || i.service.toLowerCase().includes(q)) : list;
      return filtered.map(i=>i.service+'|||'+i.subdomain);
    } else {
      const q = searchQuery.toLowerCase();
      let items = data.undetect || [];
      if(q){
        items = items.filter(i=>{
          const hay = [i.subdomain,i.rootdomain,i.potential,i.title,String(i.status_code),
            (i.cname_records||[]).join(' '),(i.a_records||[]).join(' '),i.redirect_url||'',i.reason||''].join(' ').toLowerCase();
          return hay.includes(q);
        });
      }
      return items.map(i=>i.subdomain);
    }
  }

  // Gets keys only on the CURRENT pagination page
  function getVisiblePageKeys(){
    if(activeTab==='vulns'){
      const q = searchQuery.toLowerCase();
      let list = getVulnsList();
      if(q){
        list = list.filter(i=>i.subdomain.toLowerCase().includes(q) || i.service.toLowerCase().includes(q));
      }
      if(vulnSortCol){
        list = [...list].sort((a,b)=>{
          let va = a[vulnSortCol]??'', vb = b[vulnSortCol]??'';
          va = String(va).toLowerCase(); vb = String(vb).toLowerCase();
          if(va<vb) return vulnSortAsc?-1:1;
          if(va>vb) return vulnSortAsc?1:-1;
          return 0;
        });
      }
      const pageSlice = list.slice((vulnPage - 1) * pageSize, vulnPage * pageSize);
      return pageSlice.map(i=>i.service+'|||'+i.subdomain);
    } else {
      const q = searchQuery.toLowerCase();
      let items = data.undetect || [];
      if(q){
        items = items.filter(i=>{
          const hay = [i.subdomain,i.rootdomain,i.potential,i.title,String(i.status_code),
            (i.cname_records||[]).join(' '),(i.a_records||[]).join(' '),i.redirect_url||'',i.reason||''].join(' ').toLowerCase();
          return hay.includes(q);
        });
      }
      if(undSortCol){
        items = [...items].sort((a,b)=>{
          let va = a[undSortCol]??'', vb = b[undSortCol]??'';
          if(undSortCol==='status_code'){va=Number(va);vb=Number(vb)}
          else{va=String(va).toLowerCase();vb=String(vb).toLowerCase()}
          if(va<vb) return undSortAsc?-1:1;
          if(va>vb) return undSortAsc?1:-1;
          return 0;
        });
      }
      const pageSlice = items.slice((undPage - 1) * pageSize, undPage * pageSize);
      return pageSlice.map(i=>i.subdomain);
    }
  }

  function getVulnsList() {
    const list = [];
    for (const [svc, subs] of Object.entries(data.vulns || {})) {
      for (const s of subs) {
        list.push({ subdomain: s, service: svc });
      }
    }
    return list;
  }

  // ── Render ─────────────────────────────────────────────────────
  function render(){
    $('statVulns').textContent    = data.stats.total_vuln_subdomains || 0;
    $('statServices').textContent = data.stats.total_vuln_services   || 0;
    $('statUndetect').textContent = data.stats.total_undetect        || 0;
    $('badgeVulns').textContent   = data.stats.total_vuln_subdomains || 0;
    $('badgeUndetect').textContent= data.stats.total_undetect        || 0;
    renderVulns();
    renderUndetect();
    updateToolbar();
  }

  // ── Pagination Helper ──────────────────────────────────────────
  function renderPagination(tab, totalItems){
    const container = $(tab === 'vulns' ? 'vulnPag' : 'undPag');
    if(!container) return;
    const page = tab === 'vulns' ? vulnPage : undPage;
    const totalPages = Math.ceil(totalItems / pageSize) || 1;
    
    if(totalItems <= pageSize) {
      container.innerHTML = '';
      return;
    }
    
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, totalItems);
    
    let navHtml = `<button class="pag-btn" ${page === 1 ? 'disabled' : ''} data-dir="prev">Prev</button>`;
    
    const maxButtons = 5;
    let startPage = Math.max(1, page - 2);
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);
    if(endPage - startPage + 1 < maxButtons){
      startPage = Math.max(1, endPage - maxButtons + 1);
    }
    
    for(let p = startPage; p <= endPage; p++){
      navHtml += `<button class="pag-btn${p === page ? ' active' : ''}" data-page="${p}">${p}</button>`;
    }
    
    navHtml += `<button class="pag-btn" ${page === totalPages ? 'disabled' : ''} data-dir="next">Next</button>`;
    
    container.innerHTML = `
      <div class="pag-info">Showing ${start}-${end} of ${totalItems} items</div>
      <div class="pag-nav">${navHtml}</div>
    `;
    
    container.querySelectorAll('.pag-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        if(btn.dataset.dir === 'prev') {
          if(tab === 'vulns') vulnPage--; else undPage--;
        } else if(btn.dataset.dir === 'next') {
          if(tab === 'vulns') vulnPage++; else undPage++;
        } else if(btn.dataset.page) {
          const target = +btn.dataset.page;
          if(tab === 'vulns') vulnPage = target; else undPage = target;
        }
        if(tab === 'vulns') renderVulns(); else renderUndetect();
        syncSelectAllChk();
      });
    });
  }

  // ── Vulns ──────────────────────────────────────────────────────
  function renderVulns(){
    const q = searchQuery.toLowerCase();
    let items = getVulnsList();
    if(q){
      items = items.filter(i=>i.subdomain.toLowerCase().includes(q) || i.service.toLowerCase().includes(q));
    }
    
    if(vulnSortCol){
      items = [...items].sort((a,b)=>{
        let va = a[vulnSortCol]??'', vb = b[vulnSortCol]??'';
        va = String(va).toLowerCase(); vb = String(vb).toLowerCase();
        if(va<vb) return vulnSortAsc?-1:1;
        if(va>vb) return vulnSortAsc?1:-1;
        return 0;
      });
    }

    const totalCount = items.length;
    // Slicing for pagination
    const totalPages = Math.ceil(totalCount / pageSize) || 1;
    if(vulnPage > totalPages) vulnPage = totalPages;
    const sliced = items.slice((vulnPage - 1) * pageSize, vulnPage * pageSize);

    if(!sliced.length){
      vulnBody.innerHTML = `<tr><td colspan="4">${emptyState('No vulnerabilities found','Run a scan with -lm to save results locally')}</td></tr>`;
      renderPagination('vulns', 0);
      return;
    }

    vulnBody.innerHTML = sliced.map(item => {
      const key = item.service+'|||'+item.subdomain;
      const isSel = selectedVulns.has(key);
      const svcMeta = (data.service_map && data.service_map[item.service]) || {};
      const logoUrl = svcMeta.logo;
      const displayName = svcMeta.name || item.service;
      const refUrl = svcMeta.reference;
      
      let serviceHtml = `<div class="service-container">`;
      if (logoUrl) {
        serviceHtml += `<img class="service-logo" src="${esc(logoUrl)}" alt="${esc(item.service)}" onerror="this.style.display='none'; this.nextElementSibling.style.display='grid';" />`;
      }
      const initials = item.service.slice(0,2).toUpperCase();
      serviceHtml += `<div class="service-logo-fallback" style="${logoUrl ? 'display:none;' : ''}">${esc(initials)}</div>`;
      serviceHtml += `<span>${esc(displayName)}</span></div>`;

      let actionHtml = `<div class="action-container">`;
      actionHtml += `<button class="action-btn copy-btn" data-sub="${esc(item.subdomain)}" title="Copy subdomain to clipboard"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button>`;
      if (refUrl) {
        actionHtml += `<a href="${esc(refUrl)}" target="_blank" rel="noopener noreferrer" class="action-btn ref-btn" title="View takeover guide"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>Guide</a>`;
      }
      actionHtml += `</div>`;

      const targetUrl = item.subdomain.startsWith('http') ? item.subdomain : `http://${item.subdomain}`;

      return `<tr class="${isSel?'selected':''}" data-key="${esc(key)}">
        <td style="padding-left:1rem"><input type="checkbox" class="chk vuln-chk" ${isSel?'checked':''} data-key="${esc(key)}"/></td>
        <td class="mono"><a href="${esc(targetUrl)}" target="_blank" rel="noopener noreferrer" class="subdomain-link">${esc(item.subdomain)}</a></td>
        <td>${serviceHtml}</td>
        <td style="padding-right:1rem">${actionHtml}</td>
      </tr>`;
    }).join('');

    renderPagination('vulns', totalCount);
    attachVulnListeners();
  }

  function attachVulnListeners(){
    vulnBody.querySelectorAll('.vuln-chk').forEach(cb=>{
      cb.addEventListener('change',e=>{
        e.stopPropagation();
        if(cb.checked) selectedVulns.add(cb.dataset.key); else selectedVulns.delete(cb.dataset.key);
        cb.closest('tr').classList.toggle('selected',cb.checked);
        updateToolbar();
      });
    });
    vulnBody.querySelectorAll('tr').forEach(row=>{
      row.addEventListener('click',e=>{
        if(e.target.closest('a') || e.target.closest('button') || e.target.classList.contains('chk')) return;
        const cb = row.querySelector('.chk');
        if(!cb) return;
        cb.checked = !cb.checked;
        cb.dispatchEvent(new Event('change'));
      });
    });
    vulnBody.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const sub = btn.dataset.sub;
        navigator.clipboard.writeText(sub).then(() => {
          const orig = btn.innerHTML;
          btn.innerHTML = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>Copied!`;
          setTimeout(() => { btn.innerHTML = orig; }, 1500);
        }).catch(err => console.error('Failed to copy', err));
      });
    });
  }

  // ── Undetect ───────────────────────────────────────────────────
  function renderUndetect(){
    const q = searchQuery.toLowerCase();
    let items = data.undetect || [];
    if(q){
      items = items.filter(i=>{
        const hay = [i.subdomain,i.rootdomain,i.potential,i.title,String(i.status_code),
          (i.cname_records||[]).join(' '),(i.a_records||[]).join(' '),i.redirect_url||'',i.reason||''].join(' ').toLowerCase();
        return hay.includes(q);
      });
    }
    if(undSortCol){
      items = [...items].sort((a,b)=>{
        let va = a[undSortCol]??'', vb = b[undSortCol]??'';
        if(undSortCol==='status_code'){va=Number(va);vb=Number(vb)}
        else{va=String(va).toLowerCase();vb=String(vb).toLowerCase()}
        if(va<vb) return undSortAsc?-1:1;
        if(va>vb) return undSortAsc?1:-1;
        return 0;
      });
    }

    const totalCount = items.length;
    // Slicing for pagination
    const totalPages = Math.ceil(totalCount / pageSize) || 1;
    if(undPage > totalPages) undPage = totalPages;
    const sliced = items.slice((undPage - 1) * pageSize, undPage * pageSize);

    if(!sliced.length){
      undetectBody.innerHTML = `<tr><td colspan="10">${emptyState('No undetected entries found','Run a scan with -lm to save results locally')}</td></tr>`;
      renderPagination('undetect', 0);
      return;
    }
    undetectBody.innerHTML = sliced.map(i=>{
      const sc = i.status_code||0;
      const badgeCls = sc>=200&&sc<300?'badge-2xx':sc>=300&&sc<400?'badge-3xx':sc>=400&&sc<500?'badge-4xx':sc>=500?'badge-5xx':'badge-other';
      const cnames = (i.cname_records||[]).map(c=>`<span class="cname-tag">${esc(c)}</span>`).join('') || '<span style="color:var(--text-muted)">&mdash;</span>';
      const aRecs = (i.a_records||[]).map(a=>`<span class="a-record">${esc(a)}</span>`).join('') || '<span style="color:var(--text-muted)">&mdash;</span>';
      const redir = i.redirect_url && i.redirect_url!=='No redirects' ? esc(i.redirect_url) : '<span style="color:var(--text-muted)">&mdash;</span>';
      
      const pot = i.potential || 'Unanalyz';
      let potCls = 'badge-other';
      if (pot === 'New Potential') potCls = 'badge-3xx';
      else if (pot === 'NOT VULN') potCls = 'badge-2xx';

      const reasonHtml = i.reason ? esc(i.reason) : '<span style="color:var(--text-muted)">&mdash;</span>';
      const reasonRefHtml = i.ai_reference ? ` <a href="${esc(i.ai_reference)}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:underline;font-size:.75rem;margin-left:.35rem">Guide</a>` : '';

      const isSel = selectedUndetect.has(i.subdomain);
      const targetUrl = i.subdomain.startsWith('http') ? i.subdomain : `http://${i.subdomain}`;
      
      return `<tr class="${isSel?'selected':''}" data-sub="${esc(i.subdomain)}">
        <td style="padding-left:1rem"><input type="checkbox" class="chk und-chk" ${isSel?'checked':''} data-sub="${esc(i.subdomain)}"/></td>
        <td class="mono"><a href="${esc(targetUrl)}" target="_blank" rel="noopener noreferrer" class="subdomain-link">${esc(i.subdomain||'')}</a></td>
        <td class="mono">${esc(i.rootdomain||'')}</td>
        <td><span class="badge-status ${potCls}">${esc(pot)}</span></td>
        <td>${esc(i.title||'')}</td>
        <td><span class="badge-status ${badgeCls}">${sc}</span></td>
        <td>${cnames}</td>
        <td>${aRecs}</td>
        <td style="font-size:.8rem">${redir}</td>
        <td><div class="reason-text" title="Click to expand/collapse">${reasonHtml}${reasonRefHtml}</div></td>
      </tr>`;
    }).join('');

    renderPagination('undetect', totalCount);
    attachUndetectListeners();
  }

  function attachUndetectListeners(){
    undetectBody.querySelectorAll('.und-chk').forEach(cb=>{
      cb.addEventListener('change',e=>{
        e.stopPropagation();
        if(cb.checked) selectedUndetect.add(cb.dataset.sub); else selectedUndetect.delete(cb.dataset.sub);
        cb.closest('tr').classList.toggle('selected',cb.checked);
        updateToolbar();
      });
    });
    undetectBody.querySelectorAll('tr').forEach(row=>{
      row.addEventListener('click',e=>{
        if(e.target.closest('a') || e.target.classList.contains('chk') || e.target.closest('.reason-text')) return;
        const cb = row.querySelector('.chk');
        if(!cb) return;
        cb.checked = !cb.checked;
        cb.dispatchEvent(new Event('change'));
      });
    });
    undetectBody.querySelectorAll('.reason-text').forEach(el => {
      el.addEventListener('click', e => {
        e.stopPropagation();
        el.classList.toggle('expanded');
      });
    });
  }

  // ── Utilities ──────────────────────────────────────────────────
  function emptyState(msg,hint){
    return `<div class="empty">
      <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M9 12h6m-3-3v6m-7 4h14a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2Z"/></svg>
      <p>${msg}</p>
      ${hint?`<p class="hint">${hint}</p>`:''}
    </div>`;
  }

  function esc(s){
    const d=document.createElement('div');d.textContent=s;return d.innerHTML;
  }

  // ── Tab switching ──────────────────────────────────────────────
  document.querySelectorAll('.tab-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.dataset.tab;
      document.getElementById('panel'+activeTab.charAt(0).toUpperCase()+activeTab.slice(1)).classList.add('active');
      searchInput.value='';searchQuery='';clearBtn.classList.remove('show');
      vulnPage = 1;
      undPage = 1;
      render();
    });
  });

  // ── Search ─────────────────────────────────────────────────────
  searchInput.addEventListener('input',e=>{
    searchQuery=e.target.value;
    clearBtn.classList.toggle('show',!!searchQuery);
    vulnPage = 1;
    undPage = 1;
    if(activeTab==='vulns') renderVulns(); else renderUndetect();
    syncSelectAllChk();
  });
  clearBtn.addEventListener('click',()=>{
    searchInput.value='';searchQuery='';clearBtn.classList.remove('show');
    vulnPage = 1;
    undPage = 1;
    render();
  });

  // ── Sort ───────────────────────────────────────────────────────
  document.querySelectorAll('th[data-sort]').forEach(th=>{
    th.addEventListener('click',()=>{
      const col=th.dataset.sort;
      const isVuln = th.closest('.tab-panel').id === 'panelVulns';
      if(isVuln){
        if(vulnSortCol===col){vulnSortAsc=!vulnSortAsc}else{vulnSortCol=col;vulnSortAsc=true}
        th.closest('tr').querySelectorAll('th').forEach(t=>t.classList.remove('sorted'));
        th.classList.add('sorted');
        th.querySelector('.sort-icon').textContent = vulnSortAsc?'\u25B2':'\u25BC';
        vulnPage = 1;
        renderVulns();
      }else{
        if(undSortCol===col){undSortAsc=!undSortAsc}else{undSortCol=col;undSortAsc=true}
        th.closest('tr').querySelectorAll('th').forEach(t=>t.classList.remove('sorted'));
        th.classList.add('sorted');
        th.querySelector('.sort-icon').textContent = undSortAsc?'\u25B2':'\u25BC';
        undPage = 1;
        renderUndetect();
      }
    });
  });

  // ── Select All (vulns) ─────────────────────────────────────────
  // Selecting all matches elements across ALL pages of the current search results
  vulnAllChk.addEventListener('change',()=>{
    const keys = getVisibleKeys();
    if(vulnAllChk.checked){ keys.forEach(k=>selectedVulns.add(k)); }
    else { keys.forEach(k=>selectedVulns.delete(k)); }
    renderVulns();
    updateToolbar();
  });

  // ── Select All (undetect) ──────────────────────────────────────
  undAllChk.addEventListener('change',()=>{
    const keys = getVisibleKeys();
    if(undAllChk.checked){ keys.forEach(k=>selectedUndetect.add(k)); }
    else { keys.forEach(k=>selectedUndetect.delete(k)); }
    renderUndetect();
    updateToolbar();
  });

  // ── Toolbar actions ────────────────────────────────────────────
  $('btnClearSel').addEventListener('click',()=>{
    if(activeTab==='vulns') selectedVulns.clear(); else selectedUndetect.clear();
    render();
  });
  $('btnExport').addEventListener('click',()=>openExportModal());

  // ── Export modal ───────────────────────────────────────────────
  const modal = $('exportModal');

  function openExportModal(){
    $('exportCount').textContent = totalSelected();
    $('exportTab').textContent = activeTab==='vulns' ? 'Vulnerabilities' : 'Undetected';
    exportFormat = 'json';
    document.querySelectorAll('.format-option').forEach(b=>b.classList.remove('active'));
    document.querySelector('.format-option[data-format="json"]').classList.add('active');
    renderFieldGrid();
    modal.classList.add('show');
  }

  function closeModal(){modal.classList.remove('show')}
  $('modalClose').addEventListener('click',closeModal);
  $('btnCancelExport').addEventListener('click',closeModal);
  modal.addEventListener('click',e=>{if(e.target===modal) closeModal()});
  document.addEventListener('keydown',e=>{if(e.key==='Escape') closeModal()});

  document.querySelectorAll('.format-option').forEach(btn=>{
    btn.addEventListener('click',()=>{
      document.querySelectorAll('.format-option').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      exportFormat = btn.dataset.format;
    });
  });

  // ── Field grid ─────────────────────────────────────────────────
  function getFields(){ return activeTab==='vulns' ? vulnFields : undetectFields; }

  function renderFieldGrid(){
    const fields = getFields();
    const grid = $('fieldGrid');
    grid.innerHTML = fields.map((f,i)=>`
      <div class="field-toggle${f.checked?' checked':''}">
        <input type="checkbox" class="chk field-chk" data-idx="${i}" ${f.checked?'checked':''}/>
        <label><span class="field-key">${esc(f.key)}</span> ${esc(f.label)}</label>
      </div>
    `).join('');
    grid.querySelectorAll('.field-chk').forEach(cb=>{
      cb.addEventListener('change',()=>{
        fields[+cb.dataset.idx].checked = cb.checked;
        cb.closest('.field-toggle').classList.toggle('checked',cb.checked);
        updateFieldAllChk();
      });
    });
    updateFieldAllChk();
  }

  function updateFieldAllChk(){
    const fields = getFields();
    const all = fields.every(f=>f.checked);
    const some = fields.some(f=>f.checked);
    $('fieldAllChk').checked = all;
    $('fieldAllChk').indeterminate = !all && some;
  }

  $('fieldAllChk').addEventListener('change',()=>{
    const fields = getFields();
    fields.forEach(f=>f.checked=$('fieldAllChk').checked);
    renderFieldGrid();
  });

  // ── Do export ──────────────────────────────────────────────────
  $('btnDoExport').addEventListener('click',()=>{
    const fields = getFields().filter(f=>f.checked);
    if(!fields.length){alert('Select at least one field to export.');return}

    let rows = [];
    if(activeTab==='vulns'){
      for(const key of selectedVulns){
        const [svc,sub] = key.split('|||');
        const obj = {};
        for(const f of fields){
          if(f.key==='subdomain') obj.subdomain=sub;
          if(f.key==='service') obj.service=svc;
        }
        rows.push(obj);
      }
    } else {
      const allItems = data.undetect || [];
      for(const sub of selectedUndetect){
        const item = allItems.find(i=>i.subdomain===sub);
        if(!item) continue;
        const obj = {};
        for(const f of fields){ 
          if(f.key==='reason') obj.reason = item.reason ?? '';
          else if(f.key==='potential') obj.potential = item.potential ?? '';
          else obj[f.key] = item[f.key] ?? ''; 
        }
        rows.push(obj);
      }
    }

    let content, ext, mime;
    if(exportFormat==='json'){
      content = JSON.stringify(rows, null, 2);
      ext = 'json'; mime = 'application/json';
    } else if(exportFormat==='csv'){
      const keys = fields.map(f=>f.key);
      const header = keys.map(k=>'"'+k+'"').join(',');
      const lines = rows.map(r=>keys.map(k=>{
        let v = r[k];
        if(Array.isArray(v)) v = v.join('; ');
        return '"'+(String(v||'')).replace(/"/g,'""')+'"';
      }).join(','));
      content = header + '\n' + lines.join('\n');
      ext = 'csv'; mime = 'text/csv';
    } else {
      const keys = fields.map(f=>f.key);
      content = rows.map(r=>keys.map(k=>{
        let v = r[k];
        if(Array.isArray(v)) v = v.join(', ');
        return k + ': ' + (v||'');
      }).join(' | ')).join('\n');
      ext = 'txt'; mime = 'text/plain';
    }

    const blob = new Blob([content],{type:mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `subdosec_${activeTab}_export.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    closeModal();
  });

  // ── Auto-refresh ───────────────────────────────────────────────
  function startRefreshCycle(){
    countdown=30;
    clearInterval(refreshTimer);
    refreshTimer=setInterval(()=>{
      countdown--;
      $('refreshHint').textContent=`Auto-refresh in ${countdown}s`;
      if(countdown<=0){fetchData();countdown=30}
    },1000);
  }

  // ── Init ───────────────────────────────────────────────────────
  fetchData();
  startRefreshCycle();
})();
