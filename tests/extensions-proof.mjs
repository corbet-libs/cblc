// Real member/issuer round trips using fictional test identities and test keys.
// No member opening is written to disk or passed to the issuer process.
import assert from 'node:assert/strict';
import {createHash,createECDH,createPrivateKey,generateKeyPairSync,sign} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {cpus,totalmem} from 'node:os';
import {Barretenberg,BackendType,UltraHonkBackend} from '@aztec/bb.js';
import {Noir} from '@noir-lang/noir_js';
import {OPTIONS,hex,canonicalSignature,zeros} from '@corbet-labs/czkp/encoding';
import {publicInputs,witnessInputs} from '@corbet-labs/czkp/abi';
import {createProver} from '@corbet-labs/czkp/prove';
import {ExtensionWitness,extensionHashes,checkpointFromVerified,contactBytes,receiptBytes,ackBytes} from '@corbet-labs/cwlt/extensions';
import {receiptDigest} from '@corbet-labs/cwlt/hashes';
import {loadArtifacts} from '../runtime/extensions/artifacts.mjs';
import init,{prepare} from '../.extension-wasm/cwlt.js';
await init({module_or_path:await readFile('.extension-wasm/cwlt_bg.wasm')});
const transition=input=>JSON.parse(prepare(JSON.stringify(input)));
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test');
const sha=b=>createHash('sha256').update(b).digest();
const bytes=n=>new Uint8Array(32).fill(n);
const toArray=Array.from.bind(Array);
const programs=JSON.parse(await readFile(resolve(directory,'circuits.json')));
const lock=JSON.parse(await readFile('circuits/extensions/setup-lock.json'));
await mkdir(resolve(directory,'setup'),{recursive:true});
const setup={};
for(const f of lock.files){
  const response=await fetch(f.url,{headers:{'User-Agent':'LibraryValidation/1.0',...(f.range?{Range:`bytes=0-${f.bytes-1}`}:{})},redirect:'error',signal:AbortSignal.timeout(120000)});
  assert.equal(response.status,f.range?206:200);
  const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;assert(size<=f.bytes);chunks.push(chunk);}
  const data=Buffer.concat(chunks);assert.equal(data.length,f.bytes);assert.equal(sha(data).toString('hex'),f.sha256);
  setup[f.name]=data;await writeFile(resolve(directory,'setup',f.name),data);
}
const keyApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true});
const keys={};
try{await keyApi.srsInitSrs({pointsBuf:setup['g1.dat'],numPoints:lock.numPoints,g2Point:setup['g2.dat']});
  for(const kind of ['update','deposit','record'])keys[kind]=hex(await new UltraHonkBackend(programs[kind].bytecode,keyApi).getVerificationKey(OPTIONS));
}finally{await keyApi.destroy();}
const keyBytes=Buffer.from(JSON.stringify(keys));await writeFile(resolve(directory,'keys.json'),keyBytes);
const issuer=createECDH('prime256v1');issuer.setPrivateKey(Buffer.alloc(32,3));
const manifest={version:1,accountingMode:'account-extension-v1',compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:OPTIONS.verifierTarget,
  circuitSha256:sha(await readFile(resolve(directory,'circuits.json'))).toString('hex'),vkSha256:sha(keyBytes).toString('hex'),numPoints:lock.numPoints,setup:lock.files,issuerKey:toArray(issuer.getPublicKey().subarray(1))};
const manifestBytes=Buffer.from(JSON.stringify(manifest));await writeFile(resolve(directory,'manifest.json'),manifestBytes);
const configPath=resolve(directory,'config.json');await writeFile(configPath,JSON.stringify({directory,manifestSha256:sha(manifestBytes).toString('hex')}));
const artifacts=await loadArtifacts(configPath),benchmarks=[],publicCases=[];
const hashApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true});
const hashes=extensionHashes(hashApi);
const child=spawn(resolve('target/debug/examples/extension_issuer'),[configPath],{stdio:['pipe','pipe','inherit']});
let pending;const lines=createInterface({input:child.stdout});
lines.on('line',line=>{const waiter=pending;pending=undefined;if(!waiter)throw new Error('Unexpected issuer reply');waiter.resolve(JSON.parse(line));});
child.on('exit',code=>{if(pending)pending.reject(new Error(`Issuer exited ${code}`));});
async function call(request,expected=true){assert(!pending);const result=await new Promise((resolve,reject)=>{pending={resolve,reject};child.stdin.write(JSON.stringify(request)+'\n');});
  assert.equal(result.ok,expected,`Issuer ${request.op}: ${result.error??'unexpected success'}`);publicCases.push({operation:request.op,ok:result.ok,error:result.error});return result.value;}
async function proof(kind,input,label,measure=false){
  const selected=artifacts.artifacts(kind),witness=witnessInputs(selected.circuit,input),expected=publicInputs(selected.circuit,input);
  let chosen;
  for(const backendType of measure?['NativeUnixSocket','Wasm']:['NativeUnixSocket']){
    const prover=await createProver({artifacts:selected,backendType});
    try{const result=await prover.prove(witness,expected);chosen??=hex(result.proof);
      if(measure){benchmarks.push({label,kind,backend:backendType,...result.timings});console.log(`Measured ${label} ${backendType}: ${JSON.stringify(result.timings)}`);}}
    finally{await prover.destroy();}
  }
  return chosen;
}
const encodeBundle=proofs=>Buffer.from(JSON.stringify({version:1,proofs})).toString('hex');
let now=110;
async function submit(member,candidates,label,measure=false,expected=true){
  const proofs=[];
  for(let i=0;i<candidates.length;i++){
    const c=candidates[i];proofs.push({state:c.statement.nextState,inbox:toArray(c.input.inbox),proof:await proof('update',c.input,label,measure&&i===candidates.length-1)});
  }
  const first=candidates[0],last=candidates.at(-1),statement={...last.statement,previousState:first.statement.previousState};
  const update={previousInbox:{root:toArray(first.input.previous_inbox)},inbox:{root:toArray(last.input.inbox)},effect:last.update?.effect??{kind:'update'}};
  const request={op:'apply',member,statement,update,proof:encodeBundle(proofs)};
  const certificate=await call(request,expected);if(expected)last.next.certificate=certificate;
  return {next:last.next,request};
}
async function anonymous(candidate,label,measure=false){return {statement:candidate.statement,proof:encodeBundle([{proof:await proof(candidate.statement.kind,candidate.input,label,measure)}])};}
const extension={revision:1,publicRecordQuorum:2,changeTokenCost:1,depositDelaySeconds:10,minimumDepositBatch:2};
const policy={initialCredit:3,maximumAvailable:3,outgoingReservation:1,incomingReservation:1,policyRevision:1,policyValidFrom:1,policyValidUntil:2000,
  newcomerPeriod:100,rateWindow:10,newcomerAdmissions:8,maximumAdmissions:8,refillPeriod:10,refillUnits:1,abandonAfter:100};
const community=new Uint8Array(sha('community.example'));
const signing=[],entries=[],members=[];
try{
  for(let i=0;i<4;i++){
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});signing.push(key.privateKey);
    const jwk=key.publicKey.export({format:'jwk'});entries.push({memberId:sha(Buffer.alloc(48,7+i)).toString('base64url'),accountKey:Buffer.concat([Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]).toString('hex'),
      secretHash:hex(await hashes.secretHash(community,bytes(20+i))),issuedAt:1,expiresAt:10000,delegationDigest:hex(bytes(30+i))});
  }
  const checkpoint=await checkpointFromVerified(community,entries,hashes);
  await call({op:'init',policy,extension,scope:artifacts.scope,root:toArray((await import('@corbet-labs/czkp/primitives')).fieldBytes(checkpoint.root))});
  for(let i=0;i<4;i++){
    const g=await ExtensionWitness.genesis({hashes,community,policy,extension,transition,checkpoint,ownerIndex:i,ownerSecret:bytes(20+i),now:now++});
    members[i]=(await submit(7+i,[g],'genesis',i===0)).next;
  }
  const record=async(index,label,measure=false)=>anonymous(members[index].record({purpose:'forumListing',challenge:toArray(bytes(now%255)),expiresAt:now+90}),label,measure);
  const stale=await record(0,'record-below-quorum',true);
  assert.equal(await call({op:'record',record:stale.statement.record,proof:stale.proof,now}),null);
  let nonce=60;
  const signContact=(index,owner,slot)=>canonicalSignature(sign('sha256',contactBytes(community,owner,slot),{key:signing[index],dsaEncoding:'ieee-p1363'}));
  async function contact(sender,recipient){
    const n=bytes(nonce++),group=bytes(nonce++),contactPolicy=bytes(nonce++);
    const outgoing=await members[sender].reserve({peerIndex:recipient,role:0,nonce:n,group,contactPolicy,now:now++});
    members[sender]=(await submit(7+sender,[outgoing],'reserve')).next;
    const s=members[sender].slots.get(outgoing.event.toString());
    const incoming=await members[recipient].reserve({peerIndex:sender,role:1,nonce:n,group,contactPolicy,openedAt:s.admittedAt,expiresAt:s.expiresAt,now:now++});
    members[recipient]=(await submit(7+recipient,[incoming],'reserve')).next;
    const r=members[recipient].slots.get(incoming.event.toString());
    return {sender,recipient,outgoing:outgoing.event,incoming:incoming.event,senderSignature:signContact(sender,members[recipient].owner.member,r),recipientSignature:signContact(recipient,members[sender].owner.member,s)};
  }
  const first=await contact(0,1),noise=await contact(3,1);
  const burns=[];
  for(const [i,c] of [first,noise].entries()){
    const candidate=await members[1].punish(c.incoming,now++,c.senderSignature);
    const malformed=structuredClone(candidate.input);malformed.old.available=BigInt(malformed.old.available)+1n;
    await assert.rejects(new Noir(programs.update).execute(witnessInputs(programs.update,malformed)));
    members[1]=(await submit(8,[candidate],'punishment',i===0)).next;
    assert.equal(members[1].opening.reserved,BigInt(1-i));
    burns.push({member:members[1],delivery:candidate.delivery});
  }
  assert.equal(members[1].opening.available,1n);
  now=Math.ceil((now+extension.depositDelaySeconds)/10)*10;
  const deposits=[];
  for(const [i,b] of burns.entries())deposits.push(await anonymous(await b.member.deposit(b.delivery,b.member.certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'deposit',i===0));
  const batch=deposits.map(d=>({deposit:d.statement.deposit,proof:d.proof}));
  await call({op:'deposit',batch,now});
  await call({op:'deposit',batch,now}); // Exact retry cannot append twice.
  await call({op:'record',record:stale.statement.record,proof:stale.proof,now},false);
  const omitted=await members[0].reblind(now++);
  await submit(7,[omitted],'stale-frontier',false,false);
  async function drain(index){
    const queued=await call({op:'inbox',owner:toArray(members[index].owner.member)});assert(queued.entries.length>0);
    let holder=members[index];const steps=[];
    for(const entry of queued.entries){const c=await holder.consume(entry,now);steps.push(c);holder=c.next;}
    const final=await holder.reblind(now++);steps.push(final);
    members[index]=(await submit(7+index,steps,'forced-ingestion')).next;
    const empty=await call({op:'inbox',owner:toArray(members[index].owner.member)});assert.equal(empty.entries.length,0);
  }
  await drain(0);await drain(3);
  assert.equal(members[0].opening.available,2n);assert.equal(members[0].opening.punished,1n);
  await assert.rejects(members[0].expire(first.outgoing,now));
  const below=await record(0,'record-below');assert.equal(await call({op:'record',record:below.statement.record,proof:below.proof,now}),null);
  const binding=await call({op:'binding',member:7});
  const change=await members[0].changeToken(binding,now++);
  const badOwner=structuredClone(change.input);badOwner.owner=members[2].owner.member;
  await assert.rejects(new Noir(programs.update).execute(witnessInputs(programs.update,badOwner)));
  const spent=await submit(7,[change],'change-token',true);members[0]=spent.next;
  await call({op:'pins',member:7});
  await call(spent.request,false); // Same predecessor/marker cannot authorize a new request.
  console.log('Real proofs passed punishment, forced ingestion, pin spend and negative scenarios');
  await writeFile(resolve(directory,'results.json'),JSON.stringify({benchmarks,checks:publicCases,platform:{node:process.version,cpu:cpus()[0]?.model,memoryBytes:totalmem(),threads:1},scope:artifacts.scope},null,2));
}finally{child.stdin.end();await hashApi.destroy();}
