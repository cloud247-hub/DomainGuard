const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TYPES = { A:1, NS:2, CNAME:5, SOA:6, MX:15, TXT:16, AAAA:28, DS:43, RRSIG:46, DNSKEY:48, CAA:257 };
const commonSelectors = [
  'selector1','selector2','google','default','dkim','mail','smtp','email',
  's1','s2','k1','k2','k3','key1','key2','dkim1','dkim2','m1','m2',
  'mandrill','mailjet','smtpapi','protonmail','protonmail2','protonmail3',
  'zoho','zmail','dk','dkim01','dkim02','mx','news','newsletter','send','postmark'
];
const DKIM_SCAN_CONCURRENCY = 8;
const state = { report: null };

const $ = (id) => document.getElementById(id);
const escapeHtml = (s='') => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

function normalizeDomain(value) {
  let v = String(value || '').trim().toLowerCase();
  v = v.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/\.$/, '');
  if (!v || v.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i.test(v)) {
    throw new Error('Skriv inn et gyldig domene, for eksempel eksempel.no.');
  }
  return v;
}

async function dnsQuery(name, type, opts={}) {
  const params = new URLSearchParams({ name, type, do: opts.do === false ? 'false' : 'true' });
  if (opts.cd) params.set('cd','true');
  const res = await fetch(`${DOH_ENDPOINT}?${params.toString()}`, { headers: { accept:'application/dns-json' } });
  if (!res.ok) throw new Error(`DNS-tjeneren svarte med HTTP ${res.status}.`);
  return res.json();
}

function answers(r, typeName) {
  const type = TYPES[typeName];
  return (r?.Answer || []).filter(x => x.type === type);
}
function txtValues(r) {
  return answers(r,'TXT').map(x => String(x.data).replace(/^"|"$/g,'').replace(/"\s+"/g,''));
}
function firstTxtByPrefix(r, prefix) {
  return txtValues(r).find(v => v.toLowerCase().startsWith(prefix.toLowerCase())) || '';
}
function parseTagRecord(record) {
  const out = {};
  String(record || '').split(';').map(x => x.trim()).filter(Boolean).forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0,i).trim().toLowerCase()] = part.slice(i+1).trim();
  });
  return out;
}
function status(severity, label, subtitle, detail='', records=[]) {
  return { severity, label, subtitle, detail, records };
}


function dnsHost(value='') {
  return String(value || '').trim().toLowerCase().replace(/^\d+\s+/, '').replace(/\.$/, '');
}
function mxHosts(r) {
  return answers(r,'MX').map(x=>dnsHost(x.data)).filter(Boolean);
}
function nsHosts(r) {
  return answers(r,'NS').map(x=>dnsHost(x.data)).filter(Boolean);
}
function cnameHosts(r) {
  return answers(r,'CNAME').map(x=>dnsHost(x.data)).filter(Boolean);
}
function validDkimRecord(record) {
  const tags=parseTagRecord(record);
  return Boolean(tags.p && tags.p.trim());
}
function revokedDkimRecord(record) {
  const tags=parseTagRecord(record);
  return Object.prototype.hasOwnProperty.call(tags,'p') && !tags.p.trim();
}
function dkimTxtRecords(r) {
  return txtValues(r).filter(v=>/^v=DKIM1\b/i.test(v) || /(?:^|;)\s*p\s*=/.test(v));
}
function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function detectProviders(mxResult, nsResult, rootTxtResult) {
  const mx=mxHosts(mxResult);
  const ns=nsHosts(nsResult);
  const rootTxt=txtValues(rootTxtResult).join(' ').toLowerCase();
  const providers=[];
  const add=(id,name,evidence,selectors=[],extra={})=>{
    if (!evidence.length || providers.some(p=>p.id===id)) return;
    providers.push({id,name,evidence,selectors,...extra});
  };

  const isDsMx=h=>h==='mx.domeneshop.no' || h.endsWith('.domeneshop.no');
  const isDsNs=h=>/^ns[123]\.hyp\.net$/.test(h) || h.endsWith('.domeneshop.no');
  const dsMx=mx.some(isDsMx);
  const dsNs=ns.some(isDsNs);
  const dsMxManaged=mx.length>0 && mx.every(isDsMx);
  const dsNsManaged=ns.length>=2 && ns.every(isDsNs);
  const dsSpf=rootTxt.includes('_spf.domeneshop.no');
  add('domeneshop','Domeneshop',[
    dsMx?'MX: mx.domeneshop.no':'',
    dsNs?'NS: ns1/ns2/ns3.hyp.net':'',
    dsSpf?'SPF: _spf.domeneshop.no':''
  ].filter(Boolean),[],{autoDkim:Boolean(dsMxManaged && dsNsManaged),confidence:dsMxManaged&&dsNsManaged?'high':'medium'});

  const isOneMx=h=>
    h==='mx.one.com' ||
    h.endsWith('.mx.one.com') ||
    h.endsWith('.mx.service.one') ||
    /^mx\d+\.pub\.mailpod[0-9a-z-]*\.one\.com$/.test(h);
  const isOneNs=h=>/^(?:ns0?[12]|ns[12])\.one\.com$/.test(h);
  const oneMx=mx.some(isOneMx);
  const oneNs=ns.some(isOneNs);
  const oneMxManaged=mx.length>0 && mx.every(isOneMx);
  const oneNsManaged=ns.length>=2 && ns.every(isOneNs);
  const oneSpf=rootTxt.includes('_custspf.one.com');
  add('onecom','one.com',[
    oneMx?'MX: one.com':'',
    oneNs?'NS: ns01/ns02.one.com':'',
    oneSpf?'SPF: _custspf.one.com':''
  ].filter(Boolean),[],{
    autoDkim:Boolean(oneMxManaged && oneNsManaged),
    confidence:oneMxManaged&&oneNsManaged?'high':'medium',
    opaqueSelectors:true
  });

  const m365Mx=mx.some(h=>h.endsWith('.mail.protection.outlook.com'));
  const m365Spf=rootTxt.includes('spf.protection.outlook.com');
  add('microsoft365','Microsoft 365',[m365Mx?'MX: mail.protection.outlook.com':'',m365Spf?'SPF: spf.protection.outlook.com':''].filter(Boolean),['selector1','selector2']);

  const googleMx=mx.some(h=>h==='aspmx.l.google.com' || h.endsWith('.google.com') || h.endsWith('.googlemail.com'));
  const googleSpf=rootTxt.includes('_spf.google.com');
  add('google','Google Workspace',[googleMx?'MX: Google':'',googleSpf?'SPF: _spf.google.com':''].filter(Boolean),['google']);

  const sendgrid=rootTxt.includes('sendgrid.net') || mx.some(h=>h.endsWith('.sendgrid.net'));
  add('sendgrid','SendGrid',[sendgrid?'SPF/MX: sendgrid.net':''].filter(Boolean),['s1','s2']);

  const brevo=rootTxt.includes('spf.sendinblue.com') || rootTxt.includes('spf.brevo.com') || rootTxt.includes('sendinblue.com');
  add('brevo','Brevo',[brevo?'SPF: Brevo/Sendinblue':''].filter(Boolean),[]);

  const mailgun=rootTxt.includes('mailgun.org') || mx.some(h=>h.endsWith('.mailgun.org'));
  add('mailgun','Mailgun',[mailgun?'SPF/MX: mailgun.org':''].filter(Boolean),['s1','s2']);

  const postmark=rootTxt.includes('spf.mtasv.net') || rootTxt.includes('postmarkapp.com');
  add('postmark','Postmark',[postmark?'SPF: mtasv.net/Postmark':''].filter(Boolean),['postmark']);

  const ses=rootTxt.includes('amazonses.com') || mx.some(h=>h.endsWith('.amazonses.com'));
  add('amazonses','Amazon SES',[ses?'SPF/MX: amazonses.com':''].filter(Boolean),[],{opaqueSelectors:true});

  const mailchimp=rootTxt.includes('servers.mcsv.net') || rootTxt.includes('spf.mandrillapp.com') || rootTxt.includes('mandrillapp.com');
  add('mailchimp','Mailchimp / Mandrill',[mailchimp?'SPF: Mailchimp/Mandrill':''].filter(Boolean),['k1','k2','k3','mandrill']);

  return providers;
}

async function mapLimit(items, limit, worker) {
  const out=new Array(items.length);
  let next=0;
  const runners=Array.from({length:Math.min(limit,items.length)}, async ()=>{
    while (true) {
      const i=next++;
      if (i>=items.length) return;
      out[i]=await worker(items[i],i);
    }
  });
  await Promise.all(runners);
  return out;
}

async function resolveDkimTarget(name, depth=0, seen=new Set()) {
  const normalized=dnsHost(name);
  if (!normalized || depth>4 || seen.has(normalized)) return {txt:[],chain:[],error:'CNAME-kjeden kunne ikke løses sikkert'};
  seen.add(normalized);
  const [txtResult,cnameResult]=await Promise.all([
    dnsQuery(normalized,'TXT'),
    dnsQuery(normalized,'CNAME')
  ]);
  const txt=dkimTxtRecords(txtResult);
  if (txt.length) return {txt,chain:[],raw:{txt:txtResult,cname:cnameResult}};
  const targets=cnameHosts(cnameResult);
  if (!targets.length) return {txt:[],chain:[],raw:{txt:txtResult,cname:cnameResult}};
  const target=targets[0];
  const child=await resolveDkimTarget(target,depth+1,seen);
  return {txt:child.txt,chain:[target,...(child.chain||[])],raw:{txt:txtResult,cname:cnameResult,child:child.raw},error:child.error};
}

async function lookupDkimSelector(domain, selector) {
  const host=`${selector}._domainkey.${domain}`;
  try {
    const resolved=await resolveDkimTarget(host);
    const records=resolved.txt || [];
    const valid=records.filter(validDkimRecord);
    const revoked=records.filter(revokedDkimRecord);
    const hasCname=(resolved.chain||[]).length>0;
    let state='none';
    if (valid.length) state='valid';
    else if (revoked.length) state='revoked';
    else if (records.length || hasCname) state='broken';
    return {selector,host,state,records,cnameChain:resolved.chain||[],error:resolved.error||'',raw:resolved.raw};
  } catch(err) {
    return {selector,host,state:'lookup-error',records:[],cnameChain:[],error:err?.message||String(err)};
  }
}

function providerSelectorList(providers) {
  return unique(providers.flatMap(p=>p.selectors||[]));
}

function evaluateDnssec(ds, dnskey) {
  const dsRecords = answers(ds,'DS');
  const keys = answers(dnskey,'DNSKEY');
  if (dnskey.Status === 2) return status('bad','Validering feilet','DNSSEC ser ut til å være ødelagt','Den validerende DNS-tjeneren returnerte SERVFAIL ved oppslag av DNSKEY. Dette kan tyde på en feil i DNSSEC-kjeden.', []);
  if (keys.length && dnskey.AD) return status('good','Validert','DNSSEC er aktivert','DNSKEY-poster ble returnert og autentisert av den validerende DNS-tjeneren.', keys.map(x=>x.data));
  if (keys.length) return status('warn','Finnes, men ikke validert','DNSKEY ble funnet','DNSKEY finnes, men svaret ble ikke autentisert. Kontroller DS-posten hos parent-sonen og signeringskjeden.', keys.map(x=>x.data));
  if (dsRecords.length) return status('bad','DS uten DNSKEY','Mulig DNSSEC-feil','En DS-post finnes hos parent-sonen, men ingen DNSKEY ble returnert for domenet.', dsRecords.map(x=>x.data));
  return status('warn','Ikke aktivert','Ingen DNSSEC-signering funnet','Det ble ikke funnet DNSKEY for domenet.', []);
}

function evaluateMx(r) {
  const rows = answers(r,'MX').map(x => {
    const m = String(x.data).match(/^(\d+)\s+(.+)$/);
    return { priority:m?Number(m[1]):0, host:(m?m[2]:x.data).replace(/\.$/,'') };
  }).sort((a,b)=>a.priority-b.priority);

  if (!rows.length) {
    return { ...status('bad','Mangler','Ingen MX-poster','Det ble ikke funnet MX-poster. Domenet er kanskje ikke konfigurert for å motta e-post.'), parsed:[] };
  }

  if (rows.length === 1 && rows[0].host === '') {
    return { ...status('info','Null MX','Domenet mottar ikke e-post','Domenet publiserer en null MX-post og oppgir dermed at det ikke skal motta e-post.'), parsed:rows };
  }

  const validRows = rows.filter(x => x.host);
  if (!validRows.length) {
    return { ...status('bad','Ugyldig','MX-posten kunne ikke tolkes','En MX-post ble returnert, men den inneholder ikke et gyldig servernavn.', rows.map(x=>`${x.priority} ${x.host}`)), parsed:rows };
  }

  if (validRows.length === 1) {
    return {
      ...status(
        'good',
        'Konfigurert',
        '1 MX-post – gyldig oppsett',
        'Én gyldig MX-post er en normal og korrekt konfigurasjon. Flere MX-poster er bare nødvendig når e-postleverandøren bruker flere mottaksservere, for eksempel for redundans.',
        validRows.map(x=>`${x.priority} ${x.host}`)
      ),
      parsed:rows
    };
  }

  return {
    ...status(
      'good',
      'Konfigurert',
      `${validRows.length} MX-poster – gyldig oppsett`,
      'MX-postene er gyldige og angir hvilke servere som mottar e-post for domenet. Antall MX-poster styres av e-postleverandørens arkitektur og er ikke i seg selv et kvalitetskrav.',
      validRows.map(x=>`${x.priority} ${x.host}`)
    ),
    parsed:rows
  };
}

function evaluateSpf(r) {
  const all = txtValues(r).filter(v=>/^v=spf1\b/i.test(v));
  if (!all.length) return status('bad','Mangler','Ingen SPF-policy','Publiser én SPF TXT-post som beskriver hvilke systemer som har lov til å sende e-post på vegne av domenet.');
  if (all.length > 1) return status('bad','Flere poster',`${all.length} SPF-poster funnet`,'SPF skal normalt publiseres som én samlet v=spf1-post. Flere SPF-poster kan føre til PermError.', all);
  const rec = all[0];
  let sev='good', label='Konfigurert', sub='SPF-policy funnet';
  if (/\s\+all(?:\s|$)/i.test(rec)) { sev='bad'; label='Usikker'; sub='+all tillater alle avsendere'; }
  else if (/\s~all(?:\s|$)/i.test(rec)) { sev='warn'; label='Softfail'; sub='SPF avsluttes med ~all'; }
  else if (!/\s-all(?:\s|$)/i.test(rec)) { sev='warn'; label='Bør vurderes'; sub='Ingen hard fail (-all) funnet'; }
  return status(sev,label,sub,'SPF styrer hvilken utsendingsinfrastruktur som er autorisert for domenet.',[rec]);
}

function evaluateDmarc(r) {
  const rec = firstTxtByPrefix(r,'v=DMARC1');
  if (!rec) return status('bad','Mangler','Ingen DMARC-policy','DMARC bruker SPF/DKIM-alignment til å beskytte domenet mot spoofing og kan sende rapporter om autentisering.');
  const tags = parseTagRecord(rec);
  const p=(tags.p||'').toLowerCase();
  if (p==='reject') return status('good','Reject','Sterk DMARC-håndheving','Meldinger som ikke består DMARC blir bedt avvist av mottakende e-postserver.',[rec]);
  if (p==='quarantine') return status('warn','Quarantine','Delvis DMARC-håndheving','Meldinger som feiler DMARC blir bedt satt i karantene. Vurder reject når alle legitime avsendere er verifisert.',[rec]);
  if (p==='none') return status('warn','Overvåking','DMARC-policy er p=none','DMARC samler innsyn, men ber ikke mottakere håndheve en beskyttende policy.',[rec]);
  return status('warn','Bør vurderes','DMARC-posten bør kontrolleres','En DMARC-post finnes, men policyen kunne ikke klassifiseres sikkert.',[rec]);
}

function evaluateDkim(lookups, providers) {
  const valid=(lookups||[]).filter(x=>x.state==='valid');
  const broken=(lookups||[]).filter(x=>x.state==='broken' || x.state==='revoked');
  const lookupErrors=(lookups||[]).filter(x=>x.state==='lookup-error');
  const providerNames=(providers||[]).map(p=>p.name);
  const providerText=providerNames.length ? ` Identifisert e-postleverandør: ${providerNames.join(', ')}.` : '';

  if (valid.length) {
    const records=valid.flatMap(x=>x.records.map(r=>{
      const via=x.cnameChain.length?` -> ${x.cnameChain.join(' -> ')}`:'';
      return `${x.selector}${via}: ${r}`;
    }));
    return {
      ...status('good','Verifisert',`${valid.length} DKIM-selector${valid.length===1?'':'er'} verifisert`,`Minst én gyldig offentlig DKIM-nøkkel ble funnet. TXT og CNAME-kjeder kontrolleres.${providerText}`,records),
      found:valid, broken, verificationMethod:'dns', providers:providerNames
    };
  }

  if (broken.length) {
    const records=broken.map(x=>{
      const via=x.cnameChain.length?` -> ${x.cnameChain.join(' -> ')}`:'';
      const reason=x.state==='revoked'?'tom offentlig nøkkel (p=)':'CNAME/TXT ble funnet, men ingen gyldig offentlig nøkkel kunne valideres';
      return `${x.selector}${via}: ${reason}`;
    });
    return {
      ...status('bad','DKIM-feil','DKIM-post funnet, men valideringen feilet',`DomainGuard fant en eksplisitt DKIM-post eller CNAME-kjede, men kunne ikke validere en aktiv offentlig nøkkel.${providerText}`,records),
      found:[], broken, verificationMethod:'dns-error', providers:providerNames
    };
  }

  const domeneshop=(providers||[]).find(p=>p.id==='domeneshop' && p.autoDkim);
  if (domeneshop) {
    return {
      ...status('good','Automatisk aktivert','Domeneshop håndterer DNS og e-post','MX peker til mx.domeneshop.no og autoritative navneservere peker til Domeneshops ns1/ns2/ns3.hyp.net. Domeneshop oppgir at SPF, DKIM og DMARC settes opp automatisk når alle tjenestene ligger hos dem. Statusen er derfor bekreftet via leverandøroppsett selv om en unik DKIM-selector ikke ble oppdaget automatisk.',[
        'Provider: Domeneshop',
        'Deteksjon: MX + autoritative NS',
        'DKIM: automatisk administrert av Domeneshop'
      ]),
      found:[], broken:[], verificationMethod:'provider-assurance', providers:['Domeneshop']
    };
  }

  const onecom=(providers||[]).find(p=>p.id==='onecom');
  if (onecom?.autoDkim) {
    return {
      ...status('good','Automatisk aktivert','one.com håndterer DNS og e-post','MX peker til one.com sine e-postservere og autoritative navneservere er one.com sine ns01/ns02.one.com. one.com oppgir at DKIM aktiveres automatisk når både deres navneservere og e-postservere brukes. Statusen er derfor bekreftet via leverandøroppsett selv om de leverandørstyrte DKIM-selectorene ikke ble oppdaget automatisk.',[
        'Provider: one.com',
        'Deteksjon: MX + autoritative NS',
        'DKIM: automatisk administrert av one.com'
      ]),
      found:[], broken:[], verificationMethod:'provider-assurance', providers:['one.com']
    };
  }

  const ses=(providers||[]).some(p=>p.id==='amazonses');
  const onecomExternal=(providers||[]).some(p=>p.id==='onecom' && !p.autoDkim);
  const detail=onecomExternal
    ? `one.com ble identifisert som e-postleverandør, men domenet bruker ikke et komplett one.com-navneserveroppsett. one.com bruker domenespesifikke DKIM CNAME-poster når eksterne navneservere brukes, og disse selectorene kan ikke oppdages eller gjettes sikkert fra domenenavnet alene. Kontroller de konkrete DKIM-postene one.com har oppgitt for domenet.${providerText}`
    : ses
      ? `Ingen gyldig DKIM-nøkkel ble funnet med selectorene som ble testet. Amazon SES kan bruke unike Easy DKIM-selector-tokens som ikke kan gjettes fra domenenavnet alene.${providerText}`
      : `Ingen gyldig DKIM-nøkkel ble funnet med kjente eller leverandørspesifikke selectorer. DKIM-selectorer er ikke standardiserte, så dette beviser ikke at domenet mangler DKIM.${providerText}`;
  const errorNote=lookupErrors.length ? ` ${lookupErrors.length} selector-oppslag fikk i tillegg en DNS-/nettverksfeil.` : '';
  return {
    ...status('warn','Kunne ikke bekreftes','Ingen kjent DKIM-selector ble verifisert',detail+errorNote),
    found:[], broken:[], verificationMethod:'not-confirmed', providers:providerNames, lookupErrors
  };
}

function evaluateMtaSts(r) {
  const rec=firstTxtByPrefix(r,'v=STSv1');
  return rec ? status('good','Publisert','MTA-STS DNS-post funnet','_mta-sts TXT-posten finnes. Denne nettleserbaserte kontrollen validerer ikke selve HTTPS-policyfilen.',[rec]) : status('warn','Mangler','Ingen MTA-STS TXT-post','MTA-STS kan hjelpe avsendende e-postservere med å kreve autentisert TLS ved levering.');
}

function evaluateTlsRpt(r) {
  const rec=firstTxtByPrefix(r,'v=TLSRPTv1');
  return rec ? status('good','Publisert','TLS-RPT er aktivert','Domenet annonserer en adresse for rapporter om SMTP TLS-feil.',[rec]) : status('warn','Mangler','Ingen TLS-RPT-post','TLS-RPT kan gi rapporter om feil i TLS-forhandling og transportpolicy.');
}

function evaluateCaa(r) {
  const rows=answers(r,'CAA').map(x=>x.data);
  return rows.length ? status('good','Begrenset',`${rows.length} CAA-post${rows.length===1?'':'er'}`,'CAA kan begrense hvilke sertifikatutstedere som får utstede sertifikater for domenet.',rows) : status('info','Ikke satt','Ingen CAA-poster','Uten CAA er sertifikatutstedelse ikke begrenset av en CAA-policy på dette domenenavnet.');
}

function evaluateBimi(r) {
  const rec=firstTxtByPrefix(r,'v=BIMI1');
  return rec ? status('good','Publisert','BIMI-post funnet','En BIMI TXT-post ble funnet på default._bimi.',[rec]) : status('info','Ikke funnet','Ingen standard BIMI-post','BIMI er valgfritt og krever normalt sterk DMARC-håndheving.');
}

async function runScan(domain, customSelector, scanCommon) {
  $('loadingText').textContent='Henter sentrale DNS-poster';
  const names = {
    dmarc:`_dmarc.${domain}`,
    mtasts:`_mta-sts.${domain}`,
    tlsrpt:`_smtp._tls.${domain}`,
    bimi:`default._bimi.${domain}`
  };
  const [a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi] = await Promise.all([
    dnsQuery(domain,'A'), dnsQuery(domain,'AAAA'), dnsQuery(domain,'NS'), dnsQuery(domain,'SOA'),
    dnsQuery(domain,'MX'), dnsQuery(domain,'TXT'), dnsQuery(domain,'DS'), dnsQuery(domain,'DNSKEY'),
    dnsQuery(domain,'CAA'), dnsQuery(names.dmarc,'TXT'), dnsQuery(names.mtasts,'TXT'), dnsQuery(names.tlsrpt,'TXT'), dnsQuery(names.bimi,'TXT')
  ]);

  const providers=detectProviders(mx,ns,txt);
  let selectors=[];
  if (customSelector) selectors.push(...customSelector.split(',').map(s=>s.trim()).filter(Boolean));
  selectors.push(...providerSelectorList(providers));
  const providerAssuredDkim=providers.some(p=>p.autoDkim);
  if (scanCommon && !providerAssuredDkim) selectors.push(...commonSelectors);
  selectors=unique(selectors.map(s=>s.replace(/\._domainkey.*$/,'').toLowerCase()).filter(s=>/^[a-z0-9_-]{1,63}$/i.test(s))).slice(0,48);

  $('loadingText').textContent = selectors.length
    ? `Sjekker ${selectors.length} DKIM-selector${selectors.length===1?'':'er'} (TXT + CNAME)`
    : 'Vurderer e-postleverandør og policyer';
  const dkimLookups=selectors.length
    ? await mapLimit(selectors,DKIM_SCAN_CONCURRENCY,s=>lookupDkimSelector(domain,s))
    : [];

  const checks = {
    dnssec:evaluateDnssec(ds,dnskey), mx:evaluateMx(mx), spf:evaluateSpf(txt), dkim:evaluateDkim(dkimLookups,providers), dmarc:evaluateDmarc(dmarc),
    mtasts:evaluateMtaSts(mtasts), tlsrpt:evaluateTlsRpt(tlsrpt), caa:evaluateCaa(caa), bimi:evaluateBimi(bimi)
  };
  const raw={a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi,dkim:dkimLookups.map(x=>x.raw)};
  return { domain, scannedAt:new Date().toISOString(), selectorsChecked:selectors, providers, checks, raw };
}

const severityIcon = { good:'✓', warn:'!', bad:'×', info:'i' };
const severityRank = { bad:0, warn:1, info:2, good:3 };

function scoreReport(checks) {
  const weights={dnssec:15,mx:10,spf:15,dkim:15,dmarc:20,mtasts:8,tlsrpt:7,caa:5,bimi:5};
  const factor={good:1,info:.65,warn:.4,bad:0};
  let score=0;
  Object.entries(weights).forEach(([k,w])=>score+=w*(factor[checks[k].severity]??0));
  return Math.round(score);
}
function scoreLabel(score) {
  return score>=85?'Sterk':score>=70?'God':score>=50?'Bør forbedres':'Høy risiko';
}
function checkMeta(key) {
  return {
    dnssec:['DNSSEC','DNS-integritet'],
    mx:['MX','E-postruting'],
    spf:['SPF','Autoriserte avsendere'],
    dkim:['DKIM','Kryptografisk e-postsignering'],
    dmarc:['DMARC','Autentiseringspolicy'],
    mtasts:['MTA-STS','SMTP-transportpolicy'],
    tlsrpt:['TLS-RPT','Rapportering av TLS-feil'],
    caa:['CAA','Policy for sertifikatutstedere'],
    bimi:['BIMI','Logo og merkevareindikator']
  }[key];
}
function summaryCard(key,check) {
  const [name]=checkMeta(key);
  return `<article class="summary-card"><div class="summary-top"><h4>${name}</h4><span class="status-icon ${check.severity}">${severityIcon[check.severity]}</span></div><div class="summary-value">${escapeHtml(check.label)}</div><p>${escapeHtml(check.subtitle)}</p></article>`;
}

function findingText(key,c) {
  if (c.severity==='good') return null;
  const map={
    dnssec:{bad:'DNSSEC-valideringen feiler.',warn:'DNSSEC er ikke fullt validert.',info:'Kontroller DNSSEC-status.'},
    mx:{bad:'E-postruting er ikke konfigurert.',warn:'MX-konfigurasjonen bør kontrolleres.',info:'Domenet oppgir at det ikke mottar e-post.'},
    spf:{bad:'SPF mangler eller er ugyldig.',warn:'SPF-policyen kan styrkes.',info:'Kontroller SPF.'},
    dkim:{bad:'En DKIM-post ble funnet, men valideringen feilet.',warn:'DKIM kunne ikke bekreftes automatisk med kjente selectorer.',info:'Kontroller DKIM.'},
    dmarc:{bad:'DMARC-beskyttelse mangler.',warn:'DMARC finnes, men er ikke på full håndheving.',info:'Kontroller DMARC.'},
    mtasts:{bad:'MTA-STS krever oppfølging.',warn:'MTA-STS er ikke annonsert.',info:'Kontroller MTA-STS.'},
    tlsrpt:{bad:'TLS-rapportering krever oppfølging.',warn:'SMTP TLS-rapportering er ikke aktivert.',info:'Kontroller TLS-RPT.'},
    caa:{bad:'CAA krever oppfølging.',warn:'Kontroller CAA.',info:'Ingen CAA-begrensning er publisert.'},
    bimi:{bad:'BIMI krever oppfølging.',warn:'Kontroller BIMI.',info:'BIMI ble ikke funnet. Dette er valgfritt.'}
  };
  return map[key]?.[c.severity] || c.subtitle;
}

function renderFindings(checks) {
  const priority=['dnssec','dmarc','spf','dkim','mx','mtasts','tlsrpt','caa','bimi'];
  const items=priority.map(k=>({k,c:checks[k],text:findingText(k,checks[k])})).filter(x=>x.text).sort((a,b)=>severityRank[a.c.severity]-severityRank[b.c.severity]);
  const goodCore=['dnssec','mx','spf','dkim','dmarc'].filter(k=>checks[k].severity==='good');
  if (goodCore.length>=4) items.push({k:'mx',c:{severity:'good',subtitle:'De viktigste kontrollene ser sunne ut.'},text:`${goodCore.length} av 5 sentrale DNS-/e-postkontroller besto.`});
  $('findingCount').textContent=items.length;
  $('findingsList').innerHTML=items.length ? items.map(x=>`<div class="finding"><span class="finding-icon ${x.c.severity}">${severityIcon[x.c.severity]}</span><div><strong>${escapeHtml(x.text)}</strong><p>${escapeHtml(x.c.subtitle)}</p></div></div>`).join('') : '<div class="finding"><span class="finding-icon good">✓</span><div><strong>Ingen tydelige problemer funnet</strong><p>Kontrollene som ble utført ser sunne ut.</p></div></div>';
}

function fixData(key, c, domain) {
  if (c.severity === 'good') return null;
  const rua = `dmarc@${domain}`;
  const tlsrua = `tlsrpt@${domain}`;
  const data = {
    dmarc: {
      title:'Slik kommer du i gang med DMARC',
      steps:[
        'Kontroller først at alle legitime e-posttjenester bruker SPF og/eller DKIM riktig.',
        'Opprett DMARC-posten i DNS og start med overvåking (p=none).',
        'Les DMARC-rapportene og identifiser alle legitime avsendere.',
        'Når alt legitimt passerer DMARC, øk gradvis til p=quarantine og deretter p=reject.'
      ],
      records:[{name:`_dmarc.${domain}`,type:'TXT',value:`v=DMARC1; p=none; rua=mailto:${rua}; pct=100`}],
      warning:`E-postadressen ${rua} er et eksempel. Opprett den eller bruk en DMARC-rapporttjeneste. Ikke gå rett til p=reject før du vet at legitime avsendere består DMARC.`
    },
    spf: {
      title:'Slik retter du SPF',
      steps:[
        'Lag en liste over alle tjenester som faktisk sender e-post for domenet, for eksempel Microsoft 365, Google Workspace, nyhetsbrev eller fagsystemer.',
        'Finn den offisielle SPF-include-verdien hos hver leverandør.',
        'Slå alle tillatte avsendere sammen i én SPF-post.',
        'Publiser bare én v=spf1-post på rotdomenet og test på nytt.'
      ],
      records:[{name:domain,type:'TXT',value:'v=spf1 include:<SPF-VERDI-FRA-E-POSTLEVERANDØR> -all'}],
      warning:'Ikke kopier eksempelverdien direkte. En feil SPF-post kan føre til at legitim e-post havner i søppelpost eller avvises. Domenet skal normalt bare ha én SPF-post.'
    },
    dkim: c.verificationMethod==='not-confirmed' ? {
      title:'Slik bekrefter du DKIM',
      steps:[
        'Finn DKIM-selectoren hos e-postleverandøren, eller les s=-verdien i DKIM-Signature-headeren fra en faktisk sendt e-post.',
        'Skriv selectoren i DKIM-feltet i DomainGuard og kjør testen på nytt.',
        'Hvis leverandørens kontrollpanel sier at DKIM ikke er aktivert, aktiver DKIM og publiser nøyaktig TXT- eller CNAME-posten leverandøren oppgir.'
      ],
      records:[],
      warning:'Ikke opprett en ny DKIM-post bare fordi DomainGuard ikke fant en kjent selector. Manglende automatisk funn er ikke det samme som at DKIM mangler.'
    } : {
      title:'Slik retter du DKIM-feilen',
      steps:[
        'Kontroller DKIM-selectoren som DomainGuard fant og sammenlign den med verdien hos e-postleverandøren.',
        'Hvis posten er en CNAME, kontroller at hele CNAME-kjeden peker til en aktiv DKIM-nøkkel.',
        'Hvis p= er tom, er nøkkelen tilbakekalt og må erstattes eller roteres hos leverandøren.',
        'Publiser leverandørens korrekte TXT- eller CNAME-verdi og test på nytt.'
      ],
      records:[{name:`<selector>._domainkey.${domain}`,type:'TXT eller CNAME',value:'<KORREKT-VERDI-FRA-E-POSTLEVERANDØREN>'}],
      warning:'Ikke generer eller endre DKIM-nøkkelen manuelt med mindre e-postplattformen eksplisitt krever det.'
    },
    dnssec: {
      title:'Slik aktiverer eller reparerer du DNSSEC',
      steps:[
        'Aktiver DNSSEC hos DNS-leverandøren som drifter den autoritative sonen.',
        'Kopier DS-informasjonen fra DNS-leverandøren til domeneregistraren dersom dette ikke gjøres automatisk.',
        'Vent på DNS-oppdatering og kjør kontrollen på nytt.',
        'Hvis DNSSEC allerede er aktivert og valideringen feiler, kontroller at DS hos registraren matcher gjeldende DNSKEY.'
      ],
      records:[],
      warning:'Feil DS-verdier kan gjøre domenet utilgjengelig for DNSSEC-validerende klienter. Endre ikke DS manuelt uten å følge instruksjonene fra DNS-leverandøren.'
    },
    mx: {
      title:'Slik konfigurerer du MX',
      steps:[
        'Finn MX-verdiene i dokumentasjonen til e-postleverandøren din.',
        'Opprett MX-postene med riktig prioritet.',
        'Fjern gamle MX-poster som ikke lenger skal motta e-post.',
        'Test domenet på nytt etter at DNS er oppdatert.'
      ],
      records:[{name:domain,type:'MX',value:'<PRIORITET> <MX-SERVER-FRA-E-POSTLEVERANDØR>'}],
      warning:'MX-servernavn og prioritet er leverandørspesifikke. Bruk verdiene fra e-postleverandøren.'
    },
    mtasts: {
      title:'Slik kommer du i gang med MTA-STS',
      steps:[
        'Opprett TXT-posten _mta-sts med en unik id-verdi.',
        `Konfigurer HTTPS på mta-sts.${domain} med gyldig sertifikat.`,
        'Publiser policyfilen på /.well-known/mta-sts.txt.',
        'Start gjerne med mode: testing før du går over til mode: enforce.'
      ],
      records:[{name:`_mta-sts.${domain}`,type:'TXT',value:'v=STSv1; id=20260810'}],
      warning:'MTA-STS krever også en HTTPS-policyfil. DNS-posten alene er ikke nok.'
    },
    tlsrpt: {
      title:'Slik aktiverer du TLS-RPT',
      steps:[
        'Velg en e-postadresse eller rapporttjeneste som skal motta TLS-rapportene.',
        'Opprett TXT-posten på _smtp._tls.',
        'Kontroller at mottaksadressen håndterer rapporter og at postkassen overvåkes.'
      ],
      records:[{name:`_smtp._tls.${domain}`,type:'TXT',value:`v=TLSRPTv1; rua=mailto:${tlsrua}`}],
      warning:`Adressen ${tlsrua} er et eksempel. Opprett postkassen eller bruk adressen fra TLS-rapporttjenesten din.`
    },
    caa: {
      title:'Slik begrenser du sertifikatutstedelse med CAA',
      steps:[
        'Finn hvilke sertifikatutstedere som faktisk brukes for domenet og tjenestene dine.',
        'Publiser CAA-poster som tillater disse utstederne.',
        'Kontroller også tredjepartstjenester før du gjør policyen for streng.'
      ],
      records:[{name:domain,type:'CAA',value:'0 issue "<DIN-SERTIFIKATUTSTEDER>"'}],
      warning:'Ikke publiser en tilfeldig CA. En for streng CAA-policy kan hindre fornyelse eller utstedelse av sertifikater.'
    },
    bimi: {
      title:'Slik kommer du i gang med BIMI',
      steps:[
        'Sørg først for at DMARC er på en håndhevende policy og at e-postautentisering fungerer stabilt.',
        'Gjør logoen tilgjengelig i korrekt SVG-format på HTTPS.',
        'Opprett BIMI TXT-posten på default._bimi.',
        'Kontroller kravene hos e-postleverandørene du ønsker logo hos; enkelte kan kreve et verifisert merke-sertifikat.'
      ],
      records:[{name:`default._bimi.${domain}`,type:'TXT',value:'v=BIMI1; l=https://<DITT-DOMENE>/logo.svg;'}],
      warning:'BIMI er valgfritt. Prioriter SPF, DKIM og DMARC før du bruker tid på BIMI.'
    }
  };
  return data[key] || null;
}

function dnsTemplate(record, index, key) {
  const payload = `${record.name}\t${record.type}\t${record.value}`;
  return `<div class="dns-template">
    <div class="dns-template-head"><strong>Forslag til DNS-post</strong><button class="copy-button" type="button" data-copy="${escapeHtml(payload)}">Kopier</button></div>
    <dl>
      <div><dt>Navn</dt><dd>${escapeHtml(record.name)}</dd></div>
      <div><dt>Type</dt><dd>${escapeHtml(record.type)}</dd></div>
      <div><dt>Verdi</dt><dd>${escapeHtml(record.value)}</dd></div>
    </dl>
  </div>`;
}

function remediationHtml(key, c, domain) {
  const fix=fixData(key,c,domain);
  if (!fix) return '';
  const steps=fix.steps.map(s=>`<li>${escapeHtml(s)}</li>`).join('');
  const records=fix.records.map((r,i)=>dnsTemplate(r,i,key)).join('');
  return `<div class="fix-box">
    <h4>${escapeHtml(fix.title)}</h4>
    <ol class="fix-steps">${steps}</ol>
    ${records}
    ${fix.warning ? `<div class="fix-warning"><strong>Før du publiserer:</strong> ${escapeHtml(fix.warning)}</div>` : ''}
  </div>`;
}

function renderChecks(checks, domain) {
  const order=['dnssec','mx','spf','dkim','dmarc','mtasts','tlsrpt','caa','bimi'];
  $('checksList').innerHTML=order.map(k=>{
    const c=checks[k], [name,desc]=checkMeta(k);
    const recs=(c.records||[]).map(r=>`<div class="record-box">${escapeHtml(r)}</div>`).join('');
    return `<article class="check-item">
      <button class="check-toggle" type="button">
        <span class="status-icon ${c.severity}">${severityIcon[c.severity]}</span>
        <span class="check-name"><strong>${name}</strong><span>${desc}</span></span>
        <span class="check-status ${c.severity}">${escapeHtml(c.label)}</span>
        <span class="chevron">⌄</span>
      </button>
      <div class="check-detail">
        <p>${escapeHtml(c.detail||c.subtitle)}</p>
        ${recs || '<div class="record-box">Ingen samsvarende DNS-post ble returnert.</div>'}
        ${remediationHtml(k,c,domain)}
      </div>
    </article>`;
  }).join('');

  document.querySelectorAll('.check-toggle').forEach(btn=>btn.addEventListener('click',()=>btn.parentElement.classList.toggle('open')));
  document.querySelectorAll('.copy-button').forEach(btn=>btn.addEventListener('click', async ()=>{
    const value=btn.dataset.copy || '';
    try {
      await navigator.clipboard.writeText(value);
      const old=btn.textContent;
      btn.textContent='Kopiert';
      setTimeout(()=>btn.textContent=old,1200);
    } catch {
      btn.textContent='Kunne ikke kopiere';
    }
  }));
}

function renderOverview(report) {
  const {raw}=report;
  const ns=answers(raw.ns,'NS').map(x=>x.data.replace(/\.$/,''));
  const a=answers(raw.a,'A').map(x=>x.data);
  const aaaa=answers(raw.aaaa,'AAAA').map(x=>x.data);
  const soa=answers(raw.soa,'SOA')[0]?.data || 'Ikke returnert';
  const providerNames=(report.providers||[]).map(p=>p.name);
  const methodLabel={
    dns:'DNS-verifisert',
    'provider-assurance':'Leverandørbekreftet',
    'not-confirmed':'Ikke bekreftet',
    'dns-error':'DNS-feil'
  }[report.checks.dkim.verificationMethod] || 'Ukjent';
  const rows=[
    ['IPv4',a.join(', ')||'Ingen'],
    ['IPv6',aaaa.join(', ')||'Ingen'],
    ['Navneservere',ns.length?`${ns.length} funnet`:'Ingen'],
    ['E-postleverandør',providerNames.join(', ')||'Ikke identifisert'],
    ['DKIM-verifisering',methodLabel],
    ['SOA',soa]
  ];
  $('dnsOverview').innerHTML=rows.map(([k,v])=>`<div><dt>${k}</dt><dd>${escapeHtml(v)}</dd></div>`).join('');
  const mx=report.checks.mx.parsed||[];
  $('mxList').innerHTML=mx.length ? mx.map(x=>`<div class="mini-item"><strong>${escapeHtml(x.host||'(null MX)')}</strong><span>Prioritet ${x.priority}</span></div>`).join('') : '<div class="empty-mini">Ingen MX-servere ble returnert.</div>';
}

function renderReport(report) {
  state.report=report;
  const {checks}=report;
  const score=scoreReport(checks);
  $('resultDomain').textContent=report.domain;
  $('scanTime').textContent=`Kontrollert ${new Date(report.scannedAt).toLocaleString(window.CLOUD247_LANGUAGE === 'en' ? 'en-GB' : 'nb-NO')}`;
  $('scoreNumber').textContent=score;
  $('scoreLabel').textContent=scoreLabel(score);
  $('scoreRing').style.setProperty('--score',`${score*3.6}deg`);
  $('summaryGrid').innerHTML=['dnssec','mx','spf','dkim','dmarc'].map(k=>summaryCard(k,checks[k])).join('');
  renderFindings(checks);
  renderChecks(checks,report.domain);
  renderOverview(report);
  $('results').classList.remove('hidden');
  setTimeout(()=>$('results').scrollIntoView({behavior:'smooth',block:'start'}),50);
}

function setBusy(busy) {
  $('scanButton').disabled=busy;
  $('loading').classList.toggle('hidden',!busy);
}
function showError(message) {
  $('errorPanel').textContent=message;
  $('errorPanel').classList.remove('hidden');
}

$('scanForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  $('errorPanel').classList.add('hidden');
  $('results').classList.add('hidden');
  try {
    const domain=normalizeDomain($('domainInput').value);
    $('domainInput').value=domain;
    setBusy(true);
    const report=await runScan(domain,$('dkimSelector').value.trim(),$('scanCommonSelectors').checked);
    renderReport(report);
    const url=new URL(location.href);
    url.searchParams.set('domain',domain);
    history.replaceState({},'',url);
  } catch(err) {
    showError(err?.message || 'Kontrollen kunne ikke fullføres.');
  } finally {
    setBusy(false);
  }
});

$('expandAll').addEventListener('click',()=>{
  const items=[...document.querySelectorAll('.check-item')];
  const allOpen=items.every(i=>i.classList.contains('open'));
  items.forEach(i=>i.classList.toggle('open',!allOpen));
  $('expandAll').textContent=allOpen?'Vis alle':'Skjul alle';
});

$('exportJson').addEventListener('click',()=>{
  if(!state.report) return;
  const blob=new Blob([JSON.stringify(state.report,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`${state.report.domain}-domainguard-${window.CLOUD247_LANGUAGE === 'en' ? 'report' : 'rapport'}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

const initial=new URLSearchParams(location.search).get('domain');
if(initial) $('domainInput').value=initial;
