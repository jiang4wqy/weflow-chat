const BOOT =
  "var RQ=null,zQ=r.app.requestSingleInstanceLock();";
const READY =
  "r.app.whenReady().then(async()=>{if(!zQ)return;kX=new e.t";

export function assertMainContract(source) {
  const count = token => source.split(token).length - 1;
  const result = {
    bootAnchorCount: count(BOOT),
    readyAnchorCount: count(READY),
    configConstructorCount: count("kX=new e.t"),
    wcdbSingletonCount: count("z=new rn")
  };
  const wcdbIndex = source.indexOf("z=new rn");
  const bootIndex = source.indexOf(BOOT);
  const readyIndex = source.indexOf(READY);
  if (Object.values(result).some(value => value !== 1) ||
      !(wcdbIndex < bootIndex && bootIndex < readyIndex)) {
    throw new Error("main_anchor_mismatch");
  }
  return result;
}

export function patchMain(source) {
  assertMainContract(source);
  const bootReplacement =
    'const __wfValidator=require("./validator-entry.cjs"),' +
    '__wfBoot=__wfValidator.prepareBoot({' +
    'app:r.app,argv:process.argv,env:process.env,' +
    'resourcesPath:process.resourcesPath});' +
    'var RQ=null,zQ=r.app.requestSingleInstanceLock();' +
    'if(!zQ){if(__wfBoot.enabled){' +
    '__wfValidator.writeEarlyFailure(__wfBoot,' +
    '"single_instance_lock_denied");}r.app.quit();}';
  const readyReplacement =
    'r.app.whenReady().then(async()=>{if(!zQ)return;' +
    'if(__wfBoot.enabled){let __wfExitCode=70;try{' +
    '__wfExitCode=await __wfValidator.runValidator({' +
    'boot:__wfBoot,ConfigService:e.t,wcdbService:z,app:r.app,' +
    'resourcesPath:(0,t.join)(process.resourcesPath,"resources")});' +
    '}catch{__wfValidator.writeEarlyFailure(__wfBoot,' +
    '"validator_unhandled");__wfExitCode=70;}finally{' +
    'let __wfShutdownTimer;try{await Promise.race([' +
    'Promise.resolve().then(()=>z.shutdown()),' +
    'new Promise(__wfResolve=>{__wfShutdownTimer=' +
    'setTimeout(__wfResolve,5000);})]);}catch{}finally{' +
    'if(__wfShutdownTimer!==void 0)' +
    'clearTimeout(__wfShutdownTimer);}r.app.exit(' +
    'Number.isInteger(__wfExitCode)?__wfExitCode:70);}return;}' +
    'kX=new e.t';
  return source.replace(BOOT, bootReplacement)
               .replace(READY, readyReplacement);
}
