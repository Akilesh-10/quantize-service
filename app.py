
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib, json, math, re

app = FastAPI()
FREEZES = {}

SAFE_MAX = 9007199254740991
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

FREEZE_CODES = {
    "INVALID_INPUT", "UNALLOWED_UNSUPPORTED_REASON", "NOT_LOADABLE",
    "CALIBRATION_MISMATCH", "TOKENIZER_MISMATCH"
}
SELECT_CODES = {
    "NOT_FROZEN", "INVALID_LINEAGE", "INVALID_POLICY", "INVALID_PREDICTIONS",
    "INVALID_MANIFEST", "AGGREGATE_FLOOR", "SIZE_LIMIT", "LATENCY_LIMIT"
}

def bad():
    return JSONResponse(status_code=400, content={"error":"INVALID_INPUT"})

def is_num(x):
    return isinstance(x, (int,float)) and not isinstance(x,bool) and math.isfinite(float(x))

def is_safe_int(x):
    return isinstance(x,int) and not isinstance(x,bool) and 0 <= x <= SAFE_MAX

def utf8_key(s):
    return str(s).encode("utf-8")

def codes_sorted(codes):
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))

def compact_sha(obj):
    b = json.dumps(obj, ensure_ascii=False, separators=(",",":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()

def file_inventory(files):
    if not isinstance(files, dict) or not files:
        return None
    inv=[]
    for name, text in files.items():
        if not isinstance(name,str) or not name or not isinstance(text,str):
            return None
        b=text.encode("utf-8")
        inv.append({"name":name, "bytes":len(b), "sha256":hashlib.sha256(b).hexdigest()})
    inv.sort(key=lambda x:x["name"].encode("utf-8"))
    return inv

def freeze_candidate(c, cal, tok, allowed):
    codes=[]
    if not isinstance(c,dict):
        return {"name":"","status":"invalid","inventory":[],"totalBytes":None,"packageDigest":None,"reasonCodes":["INVALID_INPUT"]}
    name=c.get("name")
    if not isinstance(name,str) or not name:
        codes.append("INVALID_INPUT"); name="" if name is None else str(name)
    files=c.get("files")
    inv=file_inventory(files)
    if inv is None:
        codes.append("INVALID_INPUT")
    reason=c.get("unsupportedReason")
    if reason is not None:
        if not isinstance(reason,str) or not reason:
            codes.append("INVALID_INPUT")
        elif reason not in allowed:
            codes.append("UNALLOWED_UNSUPPORTED_REASON")
    loadable=c.get("loadable")
    if not isinstance(loadable,bool):
        codes.append("INVALID_INPUT")
    if reason is None:
        if loadable is not True: codes.append("NOT_LOADABLE")
        if c.get("calibrationDigest") != cal: codes.append("CALIBRATION_MISMATCH")
        if c.get("tokenizerDigest") != tok: codes.append("TOKENIZER_MISMATCH")
    # Any unsupported reason is valid as "unsupported" only if explicitly allowed.
    # It does not require loadability/lineage matching.
    if reason is not None and isinstance(reason,str) and reason in allowed and not codes:
        status="unsupported"
    elif not codes:
        status="frozen"
    else:
        status="invalid"
    if inv is None:
        return {"name":name,"status":status,"inventory":[],"totalBytes":None,"packageDigest":None,"reasonCodes":codes_sorted(codes)}
    total=sum(x["bytes"] for x in inv)
    return {"name":name,"status":status,"inventory":inv,"totalBytes":total,
            "packageDigest":compact_sha(inv),"reasonCodes":codes_sorted(codes)}

def valid_freeze_input(d):
    if not isinstance(d,dict) or d.get("phase")!="freeze": return False
    fid=d.get("freezeId")
    if not isinstance(fid,str) or not (1<=len(fid)<=128): return False
    if not isinstance(d.get("calibrationDigest"),str) or not d["calibrationDigest"]: return False
    if not isinstance(d.get("tokenizerDigest"),str) or not d["tokenizerDigest"]: return False
    a=d.get("allowedUnsupportedReasons")
    cs=d.get("candidates")
    if not isinstance(a,list) or not isinstance(cs,list) or not cs: return False
    if any(not isinstance(x,str) or not x for x in a) or len(set(a))!=len(a): return False
    names=[]
    for c in cs:
        if not isinstance(c,dict) or not isinstance(c.get("name"),str) or not c["name"]:
            return False
        names.append(c["name"])
        if not isinstance(c.get("files"),dict) or not c["files"]: return False
        if any(not isinstance(k,str) or not k or not isinstance(v,str) for k,v in c["files"].items()): return False
    if len(set(names))!=len(names): return False
    return True

def exact_freeze_fingerprint(d):
    return json.dumps(d, ensure_ascii=False, separators=(",",":"), sort_keys=True)

def valid_policy(p):
    if not isinstance(p,dict): return False
    if not is_safe_int(p.get("maxBytes")): return False
    for k in ("aggregateFloor","maxLatencyMs"):
        if not is_num(p.get(k)) or float(p[k]) < 0: return False
    if float(p["aggregateFloor"]) > 1: return False
    rs=p.get("requiredSlices")
    co=p.get("candidateOrder")
    return isinstance(rs,dict) and isinstance(co,list) and len(co)>0

def recompute_manifest(c):
    if not isinstance(c,dict): return None
    inv=file_inventory(c.get("inventory")) if False else c.get("inventory")
    if not isinstance(inv,list): return None
    # Verify exact inventory records.
    rebuilt=[]
    for x in inv:
        if not isinstance(x,dict) or set(x.keys()) != {"name","bytes","sha256"}:
            return None
        n=x["name"]
        if not isinstance(n,str) or not n or not is_safe_int(x["bytes"]):
            return None
        if not isinstance(x["sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",x["sha256"]):
            return None
        rebuilt.append({"name":n,"bytes":x["bytes"],"sha256":x["sha256"]})
    if rebuilt != sorted(rebuilt,key=lambda z:z["name"].encode("utf-8")): return None
    if len({x["name"] for x in rebuilt}) != len(rebuilt): return None
    total=sum(x["bytes"] for x in rebuilt)
    digest=compact_sha(rebuilt)
    if c.get("totalBytes") != total or c.get("packageDigest") != digest:
        return None
    return {"name":c.get("name"),"inventory":rebuilt,"totalBytes":total,"packageDigest":digest}

def round12(x):
    return round(float(x),12)

@app.get("/health")
def health():
    return {"status":"ok"}

@app.post("/quantize")
async def quantize(req: Request):
    try:
        d=await req.json()
    except Exception:
        return bad()
    if not isinstance(d,dict) or d.get("phase") not in ("freeze","select"):
        return bad()

    if d["phase"]=="freeze":
        if not valid_freeze_input(d):
            return bad()
        fid=d["freezeId"]
        fp=exact_freeze_fingerprint(d)
        if fid in FREEZES:
            old=FREEZES[fid]
            if old["fingerprint"] != fp:
                return JSONResponse(status_code=409,content={"error":"FREEZE_ID_CONFLICT"})
            return JSONResponse(content=old["response"])
        allowed=d["allowedUnsupportedReasons"]
        out=[]
        for c in d["candidates"]:
            out.append(freeze_candidate(c,d["calibrationDigest"],d["tokenizerDigest"],set(allowed)))
        out.sort(key=lambda x:x["name"].encode("utf-8"))
        response={"freezeId":fid,"candidates":out}
        FREEZES[fid]={"fingerprint":fp,"response":response}
        return JSONResponse(content=response)

    # select
    if not isinstance(d.get("freezeId"),str) or not d["freezeId"]:
        return bad()
    if not isinstance(d.get("candidates"),list) or not isinstance(d.get("rows"),list) or not isinstance(d.get("policy"),dict):
        return bad()
    fid=d["freezeId"]
    if fid not in FREEZES:
        # produce normal selection-shaped response where possible
        return JSONResponse(content={"freezeId":fid,"selected":None,"results":[],"packageManifest":None})
    stored=FREEZES[fid]["response"]
    supplied=d["candidates"]
    # Exact equality to stored response candidates.
    if supplied != stored["candidates"]:
        # We still return per-candidate results when structurally possible.
        exact=False
    else:
        exact=True

    p=d["policy"]
    results=[]
    order=p.get("candidateOrder")
    policy_ok=valid_policy(p)
    names=[c.get("name") if isinstance(c,dict) else None for c in supplied]
    names_ok=(all(isinstance(n,str) and n for n in names) and len(set(names))==len(names) and
              isinstance(order,list) and len(order)==len(names) and
              all(isinstance(x,str) and x for x in order) and len(set(order))==len(order) and
              set(names)==set(order))
    if not policy_ok or not names_ok:
        # still return result entries for supplied candidates, with INVALID_POLICY
        for c in supplied:
            n=c.get("name") if isinstance(c,dict) else ""
            results.append({"name":n,"aggregate":None,"slices":{},"totalBytes":None,"latencyMs":None,
                             "admitted":False,"reasonCodes":["INVALID_POLICY"]})
        return JSONResponse(content={"freezeId":fid,"selected":None,"results":results,"packageManifest":None})

    stored_map={c["name"]:c for c in stored["candidates"]}
    req_order={n:i for i,n in enumerate(order)}
    rows=d["rows"]
    required=p["requiredSlices"]
    for name in order:
        rc=[]
        sc=stored_map.get(name)
        submitted=next((c for c in supplied if c.get("name")==name),None)
        manifest=recompute_manifest(submitted) if submitted is not None else None
        if sc is None or submitted is None or not exact:
            rc.append("NOT_FROZEN")
        if sc is None or submitted is None or sc.get("status") not in ("frozen","unsupported"):
            rc.append("INVALID_LINEAGE")
        if manifest is None:
            rc.append("INVALID_MANIFEST")
        total=manifest["totalBytes"] if manifest else None
        lat=d.get("latencies",{}).get(name) if isinstance(d.get("latencies"),dict) else None
        if not is_num(lat) or float(lat)<0:
            lat=None
            rc.append("INVALID_POLICY")
        agg=None; slices={}
        preds_ok=True
        if not isinstance(rows,list) or len(rows)==0:
            preds_ok=False
        else:
            correct=0
            slice_counts={}
            slice_correct={}
            for row in rows:
                if not isinstance(row,dict) or "label" not in row or "slice" not in row or not isinstance(row.get("predictions"),dict):
                    preds_ok=False; break
                label=row["label"]; pred=row["predictions"].get(name)
                if not (isinstance(label,(int,float)) and not isinstance(label,bool) and is_num(label) and
                        pred in (0,1,True,False) and not isinstance(pred,float)):
                    preds_ok=False; break
                ok=(int(pred)==int(label))
                correct += int(ok)
                sl=row["slice"]
                if not isinstance(sl,str): preds_ok=False; break
                slice_counts[sl]=slice_counts.get(sl,0)+1
                slice_correct[sl]=slice_correct.get(sl,0)+int(ok)
            if preds_ok:
                agg=round12(correct/len(rows))
                for sl in required:
                    if sl not in slice_counts:
                        rc.append(f"MISSING_SLICE:{sl}")
                    else:
                        slices[sl]=round12(slice_correct[sl]/slice_counts[sl])
            else:
                rc.append("INVALID_PREDICTIONS")
        if agg is not None and agg < float(p["aggregateFloor"]): rc.append("AGGREGATE_FLOOR")
        for sl,floor in required.items():
            if sl in slices and (not is_num(floor) or float(floor)<0 or float(floor)>1):
                rc.append("INVALID_POLICY")
            elif sl in slices and slices[sl] < float(floor): rc.append(f"SLICE_FLOOR:{sl}")
        if total is not None and total > p["maxBytes"]: rc.append("SIZE_LIMIT")
        if lat is not None and lat > float(p["maxLatencyMs"]): rc.append("LATENCY_LIMIT")
        rc=codes_sorted(rc)
        results.append({"name":name,"aggregate":agg,"slices":slices,"totalBytes":total,"latencyMs":lat,
                        "admitted":len(rc)==0,"reasonCodes":rc})
    # Ensure results order is candidateOrder; exact candidate order requirement is handled by lineage.
    admitted=[r for r in results if r["admitted"]]
    if admitted:
        selected=min(admitted,key=lambda r:(r["totalBytes"],r["latencyMs"],req_order[r["name"]]))
        sel=selected["name"]
        manifest=stored_map[sel]
    else:
        sel=None; manifest=None
    return JSONResponse(content={"freezeId":fid,"selected":sel,"results":results,"packageManifest":manifest})

# Render commonly uses $PORT. Keep this service portable.
if __name__ == "__main__":
    import os, uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT","10000")))
