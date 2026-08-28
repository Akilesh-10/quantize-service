import hashlib
import json
import math
from copy import deepcopy
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
FREEZES = {}

FREEZE_CODES = {
    "INVALID_INPUT", "UNALLOWED_UNSUPPORTED_REASON", "NOT_LOADABLE",
    "CALIBRATION_MISMATCH", "TOKENIZER_MISMATCH"
}
SELECT_CODES = {
    "NOT_FROZEN", "INVALID_LINEAGE", "INVALID_POLICY", "INVALID_PREDICTIONS",
    "INVALID_MANIFEST", "AGGREGATE_FLOOR", "SIZE_LIMIT", "LATENCY_LIMIT"
}

def bkey(s):
    return str(s).encode("utf-8")

def codes(xs):
    return sorted(set(xs), key=bkey)

def finite_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)

def safe_int(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 9007199254740991

def nonneg_num(x):
    return finite_num(x) and x >= 0

def digest(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def invalid():
    return JSONResponse({"error":"INVALID_INPUT"}, status_code=400)

def valid_freeze(req):
    if not isinstance(req, dict) or req.get("phase") != "freeze":
        return False
    if not isinstance(req.get("freezeId"), str) or not req["freezeId"] or len(req["freezeId"]) > 128:
        return False
    if not isinstance(req.get("calibrationDigest"), str) or not req["calibrationDigest"]:
        return False
    if not isinstance(req.get("tokenizerDigest"), str) or not req["tokenizerDigest"]:
        return False
    if not isinstance(req.get("allowedUnsupportedReasons"), list):
        return False
    if any(not isinstance(x, str) or not x for x in req["allowedUnsupportedReasons"]):
        return False
    if len(set(req["allowedUnsupportedReasons"])) != len(req["allowedUnsupportedReasons"]):
        return False
    cs=req.get("candidates")
    if not isinstance(cs,list) or len(cs)==0:
        return False
    names=[]
    for c in cs:
        if not isinstance(c,dict) or not isinstance(c.get("name"),str) or not c["name"]:
            return False
        names.append(c["name"])
        if not isinstance(c.get("files"),dict) or len(c["files"])==0:
            return False
        for k,v in c["files"].items():
            if not isinstance(k,str) or not k or not isinstance(v,str):
                return False
    return len(set(names))==len(names)

def freeze(req):
    if not valid_freeze(req):
        return invalid()
    fid=req["freezeId"]
    # Conflict/replay is checked only after full validation.
    out=[]
    allowed=set(req["allowedUnsupportedReasons"])
    for c in sorted(req["candidates"], key=lambda x:bkey(x["name"])):
        reason=[]
        valid_files=True
        files=c["files"]
        inv=[]
        for name,text in sorted(files.items(), key=lambda kv:bkey(kv[0])):
            if not isinstance(name,str) or not name or not isinstance(text,str):
                valid_files=False
                break
            raw=text.encode("utf-8")
            inv.append({"name":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
        if not valid_files:
            out.append({"name":c["name"],"status":"invalid","inventory":[],"totalBytes":None,"packageDigest":None,
                        "reasonCodes":["INVALID_INPUT"]})
            continue

        unsupported = c.get("unsupportedReason")
        if unsupported is not None:
            if not isinstance(unsupported,str) or not unsupported:
                reason.append("INVALID_INPUT")
            elif unsupported not in allowed:
                reason.append("UNALLOWED_UNSUPPORTED_REASON")
        if not isinstance(c.get("loadable"),bool):
            reason.append("INVALID_INPUT")
        elif not c["loadable"] and unsupported is None:
            reason.append("NOT_LOADABLE")
        if unsupported is None:
            if c.get("calibrationDigest") != req["calibrationDigest"]:
                reason.append("CALIBRATION_MISMATCH")
            if c.get("tokenizerDigest") != req["tokenizerDigest"]:
                reason.append("TOKENIZER_MISMATCH")

        if reason:
            out.append({"name":c["name"],"status":"invalid","inventory":[],"totalBytes":None,"packageDigest":None,
                        "reasonCodes":codes(reason)})
        elif unsupported is not None:
            pkg=digest(compact(inv))
            out.append({"name":c["name"],"status":"unsupported","inventory":inv,
                        "totalBytes":sum(x["bytes"] for x in inv),"packageDigest":pkg,"reasonCodes":[]})
        else:
            pkg=digest(compact(inv))
            out.append({"name":c["name"],"status":"frozen","inventory":inv,
                        "totalBytes":sum(x["bytes"] for x in inv),"packageDigest":pkg,"reasonCodes":[]})
    response={"freezeId":fid,"candidates":out}
    if fid in FREEZES:
        if FREEZES[fid] == response:
            return JSONResponse(deepcopy(response))
        return JSONResponse({"error":"FREEZE_ID_CONFLICT"},status_code=409)
    FREEZES[fid]=deepcopy(response)
    return JSONResponse(response)

def manifest_ok(c):
    inv=c.get("inventory")
    if not isinstance(inv,list):
        return False
    last=None
    total=0
    for x in inv:
        if not isinstance(x,dict) or set(x.keys()) != {"name","bytes","sha256"}:
            return False
        if not isinstance(x["name"],str) or not x["name"]:
            return False
        if not safe_int(x["bytes"]):
            return False
        if not isinstance(x["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",x["sha256"]):
            return False
        if last is not None and bkey(x["name"]) <= bkey(last):
            return False
        last=x["name"]; total += x["bytes"]
    if c.get("totalBytes") != total:
        return False
    expected=digest(compact(inv))
    return c.get("packageDigest")==expected

def valid_policy(p):
    if not isinstance(p,dict): return False
    req=["maxBytes","aggregateFloor","requiredSlices","maxLatencyMs","candidateOrder"]
    if any(k not in p for k in req): return False
    if not safe_int(p["maxBytes"]) or not finite_num(p["aggregateFloor"]) or not 0<=p["aggregateFloor"]<=1:
        return False
    if not isinstance(p["requiredSlices"],dict): return False
    if any(not isinstance(k,str) or not k or not finite_num(v) or not 0<=v<=1 for k,v in p["requiredSlices"].items()):
        return False
    if not finite_num(p["maxLatencyMs"]) or p["maxLatencyMs"]<0: return False
    if not isinstance(p["candidateOrder"],list) or not p["candidateOrder"]: return False
    if any(not isinstance(x,str) or not x for x in p["candidateOrder"]): return False
    return len(set(p["candidateOrder"]))==len(p["candidateOrder"])

def select(req):
    if not isinstance(req,dict) or req.get("phase")!="select":
        return invalid()
    fid=req.get("freezeId")
    cs=req.get("candidates")
    rows=req.get("rows")
    pol=req.get("policy")
    lats=req.get("latencies")
    if not isinstance(fid,str) or not fid or not isinstance(cs,list) or not cs or not isinstance(rows,list) or not isinstance(pol,dict) or not isinstance(lats,dict):
        return invalid()
    stored=FREEZES.get(fid)
    if stored is None:
        return JSONResponse({"freezeId":fid,"selected":None,"results":[],"packageManifest":None})
    if not valid_policy(pol):
        return JSONResponse({"freezeId":fid,"selected":None,"results":[],"packageManifest":None})
    # Exact equality against stored freeze response.
    if cs != stored["candidates"]:
        return JSONResponse({"freezeId":fid,"selected":None,"results":[],"packageManifest":None})
    stored_names=[c["name"] for c in stored["candidates"]]
    order=pol["candidateOrder"]
    if set(order)!=set(stored_names):
        return JSONResponse({"freezeId":fid,"selected":None,"results":[],"packageManifest":None})
    pos={n:i for i,n in enumerate(order)}
    ordered=sorted(cs,key=lambda c:(pos.get(c["name"],10**9),bkey(c["name"])))
    results=[]
    required=pol["requiredSlices"]
    for c in ordered:
        name=c["name"]
        rs=[]
        lineage=(c.get("status") in ("frozen","unsupported") and manifest_ok(c))
        if not lineage:
            rs.append("INVALID_LINEAGE")
        if not manifest_ok(c):
            rs.append("INVALID_MANIFEST")
        total=c.get("totalBytes") if manifest_ok(c) and safe_int(c.get("totalBytes")) else None
        latency=lats.get(name)
        if not finite_num(latency) or latency<0:
            latency=None
            rs.append("LATENCY_LIMIT")
        preds_ok=True
        correct=0
        slice_counts={k:[0,0] for k in required}
        for r in rows:
            if not isinstance(r,dict) or not safe_int(r.get("label")) or not isinstance(r.get("predictions"),dict) or name not in r["predictions"]:
                preds_ok=False; continue
            pred=r["predictions"][name]
            if pred not in (0,1):
                preds_ok=False; continue
            if pred==r["label"]: correct+=1
            sl=r.get("slice")
            if sl in slice_counts:
                slice_counts[sl][1]+=1
                if pred==r["label"]: slice_counts[sl][0]+=1
        if not preds_ok or not rows:
            aggregate=None; slices={k:None for k in required}
            rs.append("INVALID_PREDICTIONS")
        else:
            aggregate=round(correct/len(rows),12)
            slices={k:(round(v[0]/v[1],12) if v[1] else None) for k,v in slice_counts.items()}
            if aggregate < pol["aggregateFloor"]: rs.append("AGGREGATE_FLOOR")
            for k,v in slices.items():
                if v is None: rs.append("MISSING_SLICE:"+k)
                elif v < required[k]: rs.append("SLICE_FLOOR:"+k)
        if total is None or total>pol["maxBytes"]: rs.append("SIZE_LIMIT")
        if latency is None or latency>pol["maxLatencyMs"]: 
            if "LATENCY_LIMIT" not in rs: rs.append("LATENCY_LIMIT")
        admitted=(not rs and c.get("status")=="frozen")
        results.append({"name":name,"aggregate":aggregate,"slices":slices,"totalBytes":total,"latencyMs":latency,
                        "admitted":admitted,"reasonCodes":codes(rs)})
    admitted=[r for r in results if r["admitted"]]
    winner=None
    if admitted:
        winner=min(admitted,key=lambda r:(r["totalBytes"],r["latencyMs"],pos[r["name"]]))
    return JSONResponse({"freezeId":fid,"selected":winner["name"] if winner else None,
                         "results":results,
                         "packageManifest":winner if winner else None})

@app.post("/quantize")
async def quantize(req: Request):
    try:
        body=await req.json()
    except Exception:
        return invalid()
    if not isinstance(body,dict): return invalid()
    if body.get("phase")=="freeze": return freeze(body)
    if body.get("phase")=="select": return select(body)
    return invalid()

@app.get("/health")
async def health():
    return {"status":"ok"}
