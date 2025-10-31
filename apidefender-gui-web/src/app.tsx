import { useEffect, useState } from 'react'
import { apiConfig, startScan, getProgress } from './api'

function Section({title, children}:{title:string, children:any}){
  return <section style={{margin:'20px 0'}}>
    <h2 style={{marginBottom:10}}>{title}</h2>
    <div style={{padding:16, border:'1px solid #e5e7eb', borderRadius:8}}>{children}</div>
  </section>
}

function Row({label, hint, children}:{label:string, hint?:string, children:any}){
  return <label style={{display:'grid', gridTemplateColumns:'260px 1fr', gap:12, margin:'10px 0', alignItems:'center'}}>
    <div>
      <div style={{color:'#111827', fontWeight:600}}>{label}</div>
      {hint && <div style={{color:'#6b7280', fontSize:12}}>{hint}</div>}
    </div>
    <div>{children}</div>
  </label>
}

function Button({onClick, children, disabled}:{onClick?:any, children:any, disabled?:boolean}){
  return <button onClick={onClick} disabled={disabled} style={{padding:'10px 16px', background:'linear-gradient(90deg,#111827,#1f2937)', color:'#fff', border:'none', borderRadius:6, cursor:'pointer', opacity:disabled?0.6:1}}>{children}</button>
}

function Input(props:any){
  return <input {...props} style={{width:'100%', padding:'8px 10px', border:'1px solid #d1d5db', borderRadius:6}} />
}

function Select({options, value, onChange}:{options:string[], value?:string, onChange:any}){
  return <select value={value} onChange={e=>onChange(e.target.value)} style={{width:'100%', padding:'8px 10px', border:'1px solid #d1d5db', borderRadius:6}}>
    {options.map(o=> <option key={o} value={o}>{o}</option>)}
  </select>
}

function Badge({text, kind}:{text:string,kind:string}){
  const colors:any = {Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e'};
  return <span style={{background:colors[kind]||'#9ca3af', color:'#fff', padding:'2px 8px', borderRadius:999, fontSize:12}}>{text}</span>
}

function ReportView({scanId}:{scanId:string}){
  const [data,setData] = useState<any>();
  const [err,setErr] = useState<string>('');
  useEffect(()=>{ fetch(`/api/report/${scanId}/json`).then(r=> r.ok? r.json(): Promise.reject('no json')).then(setData).catch(()=>setErr('Отчёт JSON ещё не готов')) },[scanId]);
  if (err) return <div>{err}</div>;
  if (!data) return <div>Загрузка отчёта…</div>;
  const issues = (data.security||[]) as any[];
  const byCat: Record<string, any[]> = {} as any;
  issues.forEach(i=>{ const k=i.category||'Other'; (byCat[k]=byCat[k]||[]).push(i); });
  return <div>
    <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:16}}>
      <div style={{padding:12, border:'1px solid #e5e7eb', borderRadius:8}}><div style={{color:'#6b7280',fontSize:12}}>Preset</div><div style={{fontWeight:700}}>{data.meta?.preset||'—'}</div></div>
      <div style={{padding:12, border:'1px solid #e5e7eb', borderRadius:8}}><div style={{color:'#6b7280',fontSize:12}}>OpenAPI</div><div style={{fontWeight:700}}>{data.meta?.openapiVersion||'—'}</div></div>
      <div style={{padding:12, border:'1px solid #e5e7eb', borderRadius:8}}><div style={{color:'#6b7280',fontSize:12}}>Endpoints</div><div style={{fontWeight:700}}>{data.meta?.endpointsScanned||'—'}</div></div>
      <div style={{padding:12, border:'1px solid #e5e7eb', borderRadius:8}}><div style={{color:'#6b7280',fontSize:12}}>Duration</div><div style={{fontWeight:700}}>{Math.round((data.meta?.durationMs||0)/1000)}s</div></div>
    </div>
    {Object.keys(byCat).map(cat=>
      <div key={cat} style={{margin:'14px 0'}}>
        <h3 style={{margin:'8px 0'}}>{cat}</h3>
        <table style={{width:'100%', borderCollapse:'collapse'}}>
          <thead><tr><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Severity</th><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Endpoint</th><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Method</th><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Description</th></tr></thead>
          <tbody>
            {byCat[cat].map((i:any)=>
              <tr key={i.id}>
                <td style={{padding:8}}><Badge text={i.severity||'—'} kind={i.severity||''}/></td>
                <td style={{padding:8}}><code>{i.endpoint||'—'}</code></td>
                <td style={{padding:8}}>{i.method||'—'}</td>
                <td style={{padding:8}}>{i.description||'—'}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    )}
  </div>
}

export function App(){
  const [tab,setTab] = useState<'scan'|'progress'|'report'|'help'>('scan')
  const [cfg,setCfg] = useState<any>(null)
  const [help,setHelp] = useState<any>({})
  const [servers,setServers] = useState<string[]>([])
  const [form,setForm] = useState<any>({})
  const [scanId,setScanId] = useState<string>()
  const [prog,setProg] = useState<any>()

  useEffect(()=>{ apiConfig().then(c=>{ setCfg(c); setHelp(c.help||{}); setServers(c.servers||[]); setForm({
    openapi: c.defaults.openapi,
    tokenFile: c.defaults.tokenFile,
    preset: c.defaults.preset,
    timeout: c.defaults.timeout,
    logLevel: 'info',
    discoverUndocumented: true, strictContract: true,
    allowCorsWildcardPublic: true, exploitDepth: 'med', maxExploitOps: 40, safetySkipDelete: true,
  })}) },[])

  useEffect(()=>{
    if (tab==='progress' && scanId) {
      const t = setInterval(async()=>{
        const p = await getProgress(scanId);
        setProg(p)
      }, 1500)
      return ()=>clearInterval(t)
    }
  },[tab,scanId])

  function onChange(k:string, v:any){ setForm((f:any)=>({...f,[k]:v})) }

  async function onStart(){
    if (!form.baseUrl) { alert('Укажите Base URL'); return; }
    const r = await startScan(form); setScanId(r.id); setTab('progress')
  }

  return <div style={{maxWidth:1100, margin:'0 auto', padding:20, fontFamily:'system-ui, -apple-system, Segoe UI, Roboto'}}>
    <header style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'14px 0',background:'linear-gradient(90deg,#111827,#1f2937)',color:'#fff',borderRadius:12}}>
      <div style={{display:'flex',alignItems:'center',gap:12}}>
        <div style={{width:32,height:32,borderRadius:8,background:'#60a5fa'}} />
        <div>
          <div style={{fontWeight:700,letterSpacing:.3}}>API Defender</div>
          <div style={{opacity:.8,fontSize:12}}>GUI Console</div>
        </div>
      </div>
      <nav style={{display:'flex', gap:8}}>
        {['scan','progress','report','help'].map(t=>
          <button key={t} onClick={()=>setTab(t as any)} style={{background:'transparent', color:'#fff', border:'none', padding:8, borderBottom: tab===t? '2px solid #60a5fa':'2px solid transparent', cursor:'pointer'}}>{t.toUpperCase()}</button>
        )}
      </nav>
    </header>

    {tab==='scan' && cfg && <>
      <Section title="Параметры сканирования">
        <Row label="Сервер (Base URL)" hint="Выберите из списка подготовленных порталов">
          <Select options={servers.length?servers:[form.baseUrl||'']} value={form.baseUrl} onChange={(v:any)=>onChange('baseUrl',v)} />
        </Row>
        <Row label="OpenAPI (в контейнере)" hint={help.openapi}><Input value={form.openapi||''} onChange={(e:any)=>onChange('openapi',e.target.value)} /></Row>
        <Row label="JWT token file (в контейнере)" hint={help.tokenFile}><Input value={form.tokenFile||''} onChange={(e:any)=>onChange('tokenFile',e.target.value)} /></Row>
        <Row label="Preset" hint={help.preset}><Select options={cfg.presets} value={form.preset} onChange={(v:any)=>onChange('preset',v)} /></Row>
        <Row label="Timeout" hint={help.timeout}><Input value={form.timeout||''} onChange={(e:any)=>onChange('timeout',e.target.value)} /></Row>
        <Row label="Concurrency" hint="Параллельные запросы (пусто = авто)"><Input type="number" value={form.concurrency||''} onChange={(e:any)=>onChange('concurrency',e.target.value?parseInt(e.target.value):undefined)} /></Row>
        <Row label="Public paths (comma)" hint={help.publicPaths}><Input value={(form.publicPaths||[]).join(',')} onChange={(e:any)=>onChange('publicPaths', e.target.value? e.target.value.split(',').map((s:string)=>s.trim()): [])} /></Row>
        <Row label="Allow CORS * for public" hint={help.allowCorsWildcardPublic}><input type="checkbox" checked={!!form.allowCorsWildcardPublic} onChange={e=>onChange('allowCorsWildcardPublic', e.target.checked)} /></Row>
        <Row label="Exploit depth" hint={help.exploitDepth}><Select options={cfg.exploitDepth} value={form.exploitDepth} onChange={(v:any)=>onChange('exploitDepth',v)} /></Row>
        <Row label="Max exploit ops" hint={help.maxExploitOps}><Input type="number" value={form.maxExploitOps||''} onChange={(e:any)=>onChange('maxExploitOps', e.target.value?parseInt(e.target.value):undefined)} /></Row>
        <Row label="Safety skip DELETE" hint={help.safetySkipDelete}><input type="checkbox" checked={!!form.safetySkipDelete} onChange={e=>onChange('safetySkipDelete', e.target.checked)} /></Row>
        <Row label="Discover undocumented" hint={help.discoverUndocumented}><input type="checkbox" checked={!!form.discoverUndocumented} onChange={e=>onChange('discoverUndocumented', e.target.checked)} /></Row>
        <Row label="Strict contract" hint={help.strictContract}><input type="checkbox" checked={!!form.strictContract} onChange={e=>onChange('strictContract', e.target.checked)} /></Row>
        <Row label="Log level" hint={help.logLevel}><Select options={cfg.logLevels} value={form.logLevel} onChange={(v:any)=>onChange('logLevel', v)} /></Row>
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
          <div style={{color:'#6b7280'}}>Артефакты сохраняются в /out/gui_scans/&lt;id&gt; и дублируются в /out/reports/&lt;id&gt;</div>
          <Button onClick={onStart}>Запустить сканирование</Button>
        </div>
      </Section>
    </>}

    {tab==='progress' && <>
      {!scanId && <div>Нет активного сканирования</div>}
      {scanId && <Section title={`Прогресс #${scanId}`}>
        <div style={{marginBottom:12}}>Статус: <b>{prog?.status||'—'}</b>. Время: {prog? Math.floor((prog.elapsedMs||0)/1000): 0}s</div>
        <div style={{background:'#e5e7eb', height:8, borderRadius:99, overflow:'hidden', marginBottom:12}}>
          <div style={{height:'100%', width: prog?.status==='finished'? '100%':'40%', background:'#111827'}} />
        </div>
        <div style={{display:'grid', gridTemplateColumns:'1fr', gap:8, maxHeight:260, overflow:'auto', fontFamily:'ui-monospace, SFMono-Regular, Menlo', fontSize:12, background:'#111827', color:'#d1d5db', padding:12, borderRadius:8}}>
          {(prog?.lastLogLines||[]).map((l:string,i:number)=><div key={i}>{l}</div>)}
        </div>
      </Section>}
    </>}

    {tab==='report' && <>
      {!scanId && <div>Нет активного сканирования</div>}
      {scanId && <Section title="Отчёт">
        <ReportView scanId={scanId} />
        <div style={{display:'flex', gap:8, marginTop:12}}>
          <a href={`/api/report/${scanId}/pdf`} target="_blank"><Button>Скачать PDF</Button></a>
          <a href={`/api/report/${scanId}/json`} target="_blank"><Button>Скачать JSON</Button></a>
        </div>
      </Section>}
    </>}

    {tab==='help' && <>
      <Section title="HELP">
        <p>Ниже — параметры CLI и их влияние. Артефакты находятся в /out/gui_scans/&lt;id&gt; и дублируются в /out/reports/&lt;id&gt;.</p>
        <table style={{width:'100%', borderCollapse:'collapse'}}>
          <thead><tr><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Параметр</th><th style={{textAlign:'left',padding:8,borderBottom:'1px solid #e5e7eb'}}>Описание</th></tr></thead>
          <tbody>
            {Object.entries(help||{}).map(([k,v]:any)=>
              <tr key={k}><td style={{padding:8}}><code>--{k.replace(/[A-Z]/g,m=>'-'+m.toLowerCase())}</code></td><td style={{padding:8}}>{v as any}</td></tr>
            )}
          </tbody>
        </table>
        <p style={{marginTop:12}}>Примеры запуска через API см. в README. Для работы используйте volume-маунты /app/specs, /secrets и /out.</p>
      </Section>
    </>}
  </div>
}
