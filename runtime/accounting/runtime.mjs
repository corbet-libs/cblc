import { loadArtifacts, withPinnedBrowserWasm } from './artifacts.mjs';
import { OPTIONS, unhex } from './encoding.mjs';
import { accountHashes } from './hashes.mjs';
import { validateStatement } from './statement.mjs';
const exact = (value, keys) => value && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const equal=(a,b)=>a.length===b.length && a.every((v,i)=>v===b[i]);
async function runtime(options) {
  const browser=typeof globalThis.window !== 'undefined' || typeof globalThis.WorkerGlobalScope !== 'undefined';
  if (browser) {
    if (globalThis.crossOriginIsolated !== true || typeof globalThis.SharedArrayBuffer !== 'function') {
      throw new Error('Browser accounting requires cross-origin isolation and shared memory');
    }
  }
  const artifacts = await loadArtifacts({...options,loadBrowserWasm:browser,loadPeerReservation:false});
  const { Barretenberg, BackendType, UltraHonkBackend, UltraHonkVerifierBackend } = await import('@aztec/bb.js');
  const backendOptions = { backend: browser ? BackendType.WasmWorker : BackendType.Wasm,
    threads: 1, skipSrsInit: true, memory: { initial: 2048, maximum: artifacts.limits.memoryPages } };
  const api = browser
    ? await withPinnedBrowserWasm(artifacts.browserWasm, wasmPath => Barretenberg.new({ ...backendOptions, wasmPath }))
    : await Barretenberg.new(backendOptions);
  try {
    await api.srsInitSrs({ pointsBuf: artifacts.setup['g1.dat'], numPoints: artifacts.manifest.numPoints,
      g2Point: artifacts.setup['g2.dat'] });
    const verifier = new UltraHonkVerifierBackend(api);
    const scope = Object.freeze({ circuitDigest: Object.freeze(Array.from(unhex(artifacts.manifest.circuitSha256))),
      verifyingKeyDigest: Object.freeze(Array.from(unhex(artifacts.manifest.vkSha256))) });
    let busy = false, destroyed = false;
    async function exclusive(action) {
      if (busy || destroyed) throw new Error('Account runtime busy or closed');
      busy = true; try { return await action(); } finally { busy = false; }
    }
    async function verify(record) {
      if (!exact(record, ['statement','proof','proofScope']) || !exact(record.proofScope, ['circuitDigest','verifyingKeyDigest'])
          || !equal(record.proofScope.circuitDigest, scope.circuitDigest)
          || !equal(record.proofScope.verifyingKeyDigest, scope.verifyingKeyDigest)
          || typeof record.proof !== 'string' || record.proof.length === 0
          || record.proof.length > artifacts.limits.maxProofBytes * 2) throw new Error('Account proof scope/size');
      const inputs = await validateStatement(record.statement), proof = unhex(record.proof);
      if (!await verifier.verifyProof({ proof, publicInputs: inputs.map(n => '0x' + n.toString(16).padStart(64,'0')),
        verificationKey: artifacts.verificationKey }, OPTIONS)) throw new Error('Invalid account proof');
      return { verified: true, proofScope: scope };
    }
    const result = { scope, hashes: accountHashes(api), verify: record => exclusive(() => verify(record)),
      async destroy() { if (busy) throw new Error('Account runtime busy'); if (!destroyed) { destroyed = true; await api.destroy(); } } };
    return Object.freeze(result);
  } catch(error) { await api.destroy(); throw error; }
}
export const createAccountVerifier = options => runtime(options);
