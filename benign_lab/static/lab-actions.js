'use strict';
async function labRefreshPower(){
 $('lab-power-body').innerHTML='<tr><td colspan="2" class="empty">Consultando…</td></tr>';
 try{
  const states=await api('/lab/power-states',undefined,'GET');
  const rows=Object.entries(states).sort(([a],[b])=>a.localeCompare(b));
  $('lab-power-body').innerHTML=rows.length?rows.map(([name,state])=>`<tr><td>${escape(name)}</td><td>${escape(state)}</td></tr>`).join(''):'<tr><td colspan="2" class="empty">Sin VMs reportadas.</td></tr>';
 }catch(e){$('lab-power-body').innerHTML=`<tr><td colspan="2" class="empty">${escape(e.message)}</td></tr>`;}
}
async function labConnectivity(){
 const domain=$('lab-domain').value;
 $('lab-domain-result').innerHTML='<p class="help">Verificando…</p>';
 try{
  const results=await api(`/lab/connectivity/${domain}`,undefined,'GET');
  const rows=Object.entries(results);
  $('lab-domain-result').innerHTML=`<table><thead><tr><th>Nodo</th><th>Estado</th></tr></thead><tbody>${rows.map(([name,r])=>`<tr><td>${escape(name)}</td><td class="${r.ok?'':'error'}">${r.ok?'OK':escape(r.error||'sin respuesta')}</td></tr>`).join('')}</tbody></table>`;
 }catch(e){$('lab-domain-result').innerHTML=`<p class="help error">${escape(e.message)}</p>`;}
}
async function labPower(on){
 const domain=$('lab-domain').value;
 if(!confirm(`Esto va a ${on?'ENCENDER':'APAGAR'} las VMs reales del dominio "${domain}" en el laboratorio. ¿Continuar?`))return;
 $('lab-domain-result').innerHTML='<p class="help">Aplicando…</p>';
 try{
  const result=await api(`/lab/power/${domain}/${on?'on':'off'}`,{confirm:true});
  $('lab-domain-result').innerHTML=`<pre>${escape(JSON.stringify(result,null,2))}</pre>`;
  notice(`Dominio ${domain}: ${on?'encendido':'apagado'} solicitado.`);
 }catch(e){$('lab-domain-result').innerHTML=`<p class="help error">${escape(e.message)}</p>`;}
}
async function labRecover(){
 const domain=$('lab-domain').value;
 if(!confirm(`Esto va a correr el playbook de reconexión de Ansible sobre el dominio "${domain}" real. ¿Continuar?`))return;
 $('lab-domain-result').innerHTML='<p class="help">Ejecutando playbook…</p>';
 try{
  const result=await api(`/lab/recover/${domain}`,{confirm:true});
  $('lab-domain-result').innerHTML=`<pre>${escape(JSON.stringify(result,null,2))}</pre>`;
  notice(`Recuperación de ${domain} completada (código ${result.returncode}).`);
 }catch(e){$('lab-domain-result').innerHTML=`<p class="help error">${escape(e.message)}</p>`;}
}
async function labLoadAttackPlans(){
 try{
  const list=await api('/attacks/plans',undefined,'GET');
  $('attack-plans-body').innerHTML=list.length?list.map(p=>`<tr><td><code>${p.plan_hash.slice(0,12)}</code><small>seed ${p.seed} · ${p.duration_s}s</small></td><td>${p.domains.map(escape).join(', ')}</td><td>${p.events}</td><td>${escape(p.description||'')}</td><td><button class="secondary attack-start-btn" data-hash="${p.plan_hash}">Lanzar</button></td></tr>`).join(''):'<tr><td colspan="5" class="empty">Sin planes todavía.</td></tr>';
  document.querySelectorAll('.attack-start-btn').forEach(b=>b.onclick=()=>labStartAttack(b.dataset.hash));
 }catch(e){notice(e.message,true);}
}
async function labGenerateAttackPlan(){
 const raw=$('attack-flows-json').value.trim();
 let flows;
 if(raw){
  try{flows=JSON.parse(raw);}catch{notice('JSON de flujos inválido.',true);return;}
 }else{
  flows=[{domain:$('attack-domain').value,sources:$('attack-sources').value.split(',').map(s=>s.trim()).filter(Boolean),destination:$('attack-destination').value.trim(),wire_protocol:$('attack-protocol').value,rate_pps:Number($('attack-pps').value),start_s:Number($('attack-start-s').value),duration_s:Number($('attack-flow-duration').value)}];
 }
 try{
  const body={seed:Number($('attack-seed').value),duration_s:Number($('attack-duration').value),flows};
  const result=await api('/attacks/plans',body);
  $('attack-plan-hash').textContent=result.plan_hash;
  $('attack-plan-summary').textContent=`${result.events} evento(s) · dominios: ${result.domains.join(', ')}`;
  $('attack-plan-result').hidden=false;
  notice('Plan de ataque generado. Real, sin hping3: udp_flood/syn_flood/icmp_flood desde los clientes declarados.');
  await labLoadAttackPlans();
 }catch(e){notice(e.message,true);}
}
async function labStartAttack(planHash){
 if(!confirm('Esto va a enviar tráfico de ataque REAL (udp_flood/syn_flood/icmp_flood) desde clientes reales del laboratorio hacia el destino del plan. ¿Continuar?'))return;
 $('attack-start-result').textContent='Lanzando ataque…';
 try{
  const report=await api('/attacks/start',{plan_hash:planHash,confirm:true});
  const packets=Object.values(report.events).reduce((n,e)=>n+(e.packets_sent||0),0);
  $('attack-start-result').textContent=`Ataque finalizado: ${packets} paquetes enviados en total. Inicio real ${new Date(report.started_at*1000).toLocaleTimeString()}.`;
  notice('Ataque real finalizado.');
 }catch(e){$('attack-start-result').textContent='';notice(e.message,true);}
}
$('lab-power-refresh').onclick=labRefreshPower;
$('lab-connectivity').onclick=labConnectivity;
$('lab-power-on').onclick=()=>labPower(true);
$('lab-power-off').onclick=()=>labPower(false);
$('lab-recover').onclick=labRecover;
$('attack-generate').onclick=labGenerateAttackPlan;
$('attack-plans-refresh').onclick=labLoadAttackPlans;
document.querySelector('[data-view="lab-actions"]').addEventListener('click',()=>{labRefreshPower();labLoadAttackPlans();});
