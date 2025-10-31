import { useEffect, useState } from 'react'
import { apiConfig, startScan, getProgress } from './api'

function Section({title, children}:{title:string, children:any}){
  return <section style={{margin:'20px 0'}}>
    <h2 style={{marginBottom:10}}>{title}</h2>
    <div style={{padding:16, border:'1px solid #e5e7eb', borderRadius:8}}>{children}</div>
  </section>
}

function Row({label, children}:{label:string, children:any}){
  return <label style={{display:'grid', gridTemplateColumns:'220px 1fr', gap:12, margin:'8px 0', alignItems:'center'}}>
    <span style={{color:'#374151'}}>{label}</span>
    <div>{children}</div>
  </label>
}

function Button({onClick, children, disabled}:{onClick?:any, children:any, disabled?:boolean}){
  return <button onClick={onClick} disabled={disabled} style={{padding:'10px 16px', background:'#111827', color:'#fff', border:'none', borderRadius:6, cursor:'pointer', opacity:disabled?0.6:1}}>{children}</button>
}

function Input(props:any){
  return <input {...props} style={{width:'100%', padding:'8px 10px', border:'1px solid #d1d5db', borderRadius:6}} />
}

function Select({options, value, onChange}:{options:string[], value?:string, onChange:any}){
  return <select value={value} onChange={e=>onChange(e.target.value)} style={{width:'100%', padding:'8px 10px', border:'1px solid #d1d5db', borderRadius:6}}>
    {options.map(o=> <option key={o} value={o}>{o}</option>)}
  </select>
}

export function App(){
  const [tab,setTab] = useState<'scan'|'progress'|'report'|'help'>('scan')
  const [cfg,setCfg] = useState<any>(null)
  const [form,setForm] = useState<any>({})
  const [scanId,setScanId] = useState<string>()
  const [prog,setProg] = useState<any>()

  useEffect(()=>{ apiConfig().then(c=>{ setCfg(c); setForm({
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

  return <div style={{maxWidth:1000, margin:'0 auto', padding:20, fontFamily:'system-ui, -apple-system, Segoe UI, Roboto'}}>
    <header style={{display:'flex', alignItems:'center', justifyContent:'space-between'}}>
      <h1 style={{fontSize:22}}>API Defender (GUI)</h1>
      <nav style={{display:'flex', gap:8}}>
        {['scan','progress','report','help'].map(t=>
          <button key={t} onClick={()=>setTab(t as any)} style={{background:'transparent', border:'none', padding:8, borderBottom: tab===t? '2px solid #111827':'2px solid transparent'}}>{t.toUpperCase()}</button>
        )}
      </nav>
    </header>

    {tab==='scan' && cfg && <>
      <Section title="Параметры сканирования">
        <Row label="OpenAPI (в контейнере)"><Input value={form.openapi||''} onChange={(e:any)=>onChange('openapi',e.target.value)} /></Row>
        <Row label="JWT token file (в контейнере)"><Input value={form.tokenFile||''} onChange={(e:any)=>onChange('tokenFile',e.target.value)} /></Row>
        <Row label="Base URL"><Input value={form.baseUrl||''} onChange={(e:any)=>onChange('baseUrl',e.target.value)} placeholder="https://abank.open.bankingapi.ru/" /></Row>
        <Row label="Preset"><Select options={cfg.presets} value={form.preset} onChange={(v:any)=>onChange('preset',v)} /></Row>
        <Row label="Timeout"><Input value={form.timeout||''} onChange={(e:any)=>onChange('timeout',e.target.value)} /></Row>
        <Row label="Concurrency"><Input type="number" value={form.concurrency||''} onChange={(e:any)=>onChange('concurrency',e.target.value?parseInt(e.target.value):undefined)} /></Row>
        <Row label="Public paths (comma)"><Input value={(form.publicPaths||[]).join(',')} onChange={(e:any)=>onChange('publicPaths', e.target.value? e.target.value.split(',').map((s:string)=>s.trim()): [])} /></Row>
        <Row label="Allow CORS * for public"><input type="checkbox" checked={!!form.allowCorsWildcardPublic} onChange={e=>onChange('allowCorsWildcardPublic', e.target.checked)} /></Row>
        <Row label="Exploit depth"><Select options={cfg.exploitDepth} value={form.exploitDepth} onChange={(v:any)=>onChange('exploitDepth',v)} /></Row>
        <Row label="Max exploit ops"><Input type="number" value={form.maxExploitOps||''} onChange={(e:any)=>onChange('maxExploitOps', e.target.value?parseInt(e.target.value):undefined)} /></Row>
        <Row label="Safety skip DELETE"><input type="checkbox" checked={!!form.safetySkipDelete} onChange={e=>onChange('safetySkipDelete', e.target.checked)} /></Row>
        <Row label="Discover undocumented"><input type="checkbox" checked={!!form.discoverUndocumented} onChange={e=>onChange('discoverUndocumented', e.target.checked)} /></Row>
        <Row label="Strict contract"><input type="checkbox" checked={!!form.strictContract} onChange={e=>onChange('strictContract', e.target.checked)} /></Row>
        <Row label="Log level"><Select options={cfg.logLevels} value={form.logLevel} onChange={(v:any)=>onChange('logLevel', v)} /></Row>
        <div style={{display:'flex', justifyContent:'flex-end'}}><Button onClick={onStart}>Запустить сканирование</Button></div>
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
        <div style={{display:'flex', gap:8, marginBottom:8}}>
          <a href={`/api/report/${scanId}/html`} target="_blank"><Button>Открыть HTML</Button></a>
          <a href={`/api/report/${scanId}/pdf`} target="_blank"><Button>Скачать PDF</Button></a>
          <a href={`/api/report/${scanId}/json`} target="_blank"><Button>Скачать JSON</Button></a>
        </div>
        <iframe src={`/api/report/${scanId}/html`} style={{width:'100%', height:600, border:'1px solid #e5e7eb', borderRadius:8}} />
      </Section>}
    </>}

    {tab==='help' && <>
      <Section title="HELP">
        <p>CLI флаги соответствуют параметрам формы. Артефакты: HTML/PDF/JSON/лог и raw-трейсы — в /out.</p>
        <ul>
          <li>--openapi: путь к спецификации (JSON/YAML)</li>
          <li>--token-file: путь к JWT (Bearer)</li>
          <li>--preset: fast|full|aggressive</li>
          <li>--timeout: напр. 5m</li>
          <li>--public-path: CSV путей без аутентификации</li>
          <li>--allow-cors-wildcard-public</li>
          <li>--report-{html,pdf,json}, --save-traces, --log-file</li>
          <li>--log-level: info|debug</li>
          <li>--safety-skip-delete, --exploit-depth, --max-exploit-ops</li>
        </ul>
      </Section>
    </>}
  </div>
}

