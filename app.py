from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib, json, math, os

app = FastAPI()
FREEZES = {}
SAFE_MAX = 9007199254740991

FREEZE_CODES = [
    "INVALID_INPUT", "UNALLOWED_UNSUPPORTED_REASON", "NOT_LOADABLE",
    "CALIBRATION_MISMATCH", "TOKENIZER_MISMATCH"
]

def invalid_input():
    return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

def safe_int(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= SAFE_MAX

def finite_nonneg(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x)) and float(x) >= 0

def finite_unit(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x)) and 0 <= float(x) <= 1

def sort_codes(codes):
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def package_digest(inv):
    raw = json.dumps(inv, ensure_ascii=False, separators=(",", ":"))
    return sha256_bytes(raw.encode("utf-8"))

def build_inventory(files):
    if not isinstance(files, dict) or not files:
        return None
    inv=[]
    for filename, text in files.items():
        if not isinstance(filename, str) or not filename:
            return None
        if not isinstance(text, str):
            return None
        b=text.encode("utf-8")
        inv.append({
            "name": filename,
            "bytes": len(b),
            "sha256": sha256_bytes(b)
        })
    inv.sort(key=lambda x: x["name"].encode("utf-8"))
    return inv

def freeze_fingerprint(d):
    return json.dumps(d, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def valid_freeze_request(d):
    if not isinstance(d, dict) or d.get("phase") != "freeze":
        return False
    if not isinstance(d.get("freezeId"), str) or not d["freezeId"] or len(d["freezeId"]) > 128:
        return False
    if not isinstance(d.get("calibrationDigest"), str) or not d["calibrationDigest"]:
        return False
    if not isinstance(d.get("tokenizerDigest"), str) or not d["tokenizerDigest"]:
        return False
    if not isinstance(d.get("allowedUnsupportedReasons"), list):
        return False
    allowed=d["allowedUnsupportedReasons"]
    if any(not isinstance(x,str) or not x for x in allowed) or len(set(allowed)) != len(allowed):
        return False
    cs=d.get("candidates")
    if not isinstance(cs, list) or not cs:
        return False
    names=[]
    for c in cs:
        if not isinstance(c,dict):
            return False
        if not isinstance(c.get("name"),str) or not c["name"]:
            return False
        names.append(c["name"])
        if not isinstance(c.get("files"),dict) or not c["files"]:
            return False
        for k,v in c["files"].items():
            if not isinstance(k,str) or not k or not isinstance(v,str):
                return False
    return len(names)==len(set(names))

def freeze_candidate(c, req):
    codes=[]
    name=c.get("name","")
    inv=build_inventory(c.get("files"))

    if inv is None:
        codes.append("INVALID_INPUT")

    loadable=c.get("loadable")
    if not isinstance(loadable,bool):
        codes.append("INVALID_INPUT")

    reason=c.get("unsupportedReason")
    allowed=set(req["allowedUnsupportedReasons"])

    if reason is not None:
        if not isinstance(reason,str) or not reason:
            codes.append("INVALID_INPUT")
        elif reason not in allowed:
            codes.append("UNALLOWED_UNSUPPORTED_REASON")

    # An allowed unsupported reason makes the candidate unsupported.
    # Other evidence checks do not invalidate an explicitly allowed reason.
    if isinstance(reason,str) and reason in allowed and "INVALID_INPUT" not in codes:
        status="unsupported"
    else:
        if reason is None:
            if loadable is not True:
                codes.append("NOT_LOADABLE")
            if c.get("calibrationDigest") != req["calibrationDigest"]:
                codes.append("CALIBRATION_MISMATCH")
            if c.get("tokenizerDigest") != req["tokenizerDigest"]:
                codes.append("TOKENIZER_MISMATCH")
        elif isinstance(reason,str) and reason not in allowed:
            pass

        status="frozen" if not codes else "invalid"

    if inv is None:
        return {
            "name": name,
            "status": status,
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": sort_codes(codes)
        }

    total=sum(x["bytes"] for x in inv)
    return {
        "name": name,
        "status": status,
        "inventory": inv,
        "totalBytes": total,
        "packageDigest": package_digest(inv),
        "reasonCodes": sort_codes(codes)
    }

def valid_manifest(c):
    if not isinstance(c,dict):
        return False
    inv=c.get("inventory")
    if not isinstance(inv,list) or not inv:
        return False
    rebuilt=[]
    seen=set()
    for x in inv:
        if not isinstance(x,dict) or list(x.keys()) != ["name","bytes","sha256"]:
            return False
        n=x.get("name")
        if not isinstance(n,str) or not n or n in seen:
            return False
        if not safe_int(x.get("bytes")):
            return False
        h=x.get("sha256")
        if not isinstance(h,str) or len(h)!=64 or any(ch not in "0123456789abcdef" for ch in h):
            return False
        seen.add(n)
        rebuilt.append({"name":n,"bytes":x["bytes"],"sha256":h})
    if rebuilt != sorted(rebuilt,key=lambda z:z["name"].encode("utf-8")):
        return False
    total=sum(x["bytes"] for x in rebuilt)
    if c.get("totalBytes") != total:
        return False
    if c.get("packageDigest") != package_digest(rebuilt):
        return False
    return True

def select_policy_valid(p):
    if not isinstance(p,dict):
        return False
    if not safe_int(p.get("maxBytes")):
        return False
    if not finite_unit(p.get("aggregateFloor")):
        return False
    if not finite_nonneg(p.get("maxLatencyMs")):
        return False
    rs=p.get("requiredSlices")
    co=p.get("candidateOrder")
    if not isinstance(rs,dict) or not isinstance(co,list) or not co:
        return False
    if any(not isinstance(k,str) or not k or not finite_unit(v) for k,v in rs.items()):
        return False
    if any(not isinstance(x,str) or not x for x in co):
        return False
    return len(co)==len(set(co))

def prediction_binary(x):
    return (isinstance(x,int) and not isinstance(x,bool) and x in (0,1))

@app.get("/health")
def health():
    return {"status":"ok"}

@app.post("/quantize")
async def quantize(req: Request):
    try:
        d=await req.json()
    except Exception:
        return invalid_input()

    if not isinstance(d,dict) or d.get("phase") not in ("freeze","select"):
        return invalid_input()

    if d["phase"]=="freeze":
        if not valid_freeze_request(d):
            return invalid_input()

        fid=d["freezeId"]
        fp=freeze_fingerprint(d)

        if fid in FREEZES:
            if FREEZES[fid]["fingerprint"] != fp:
                return JSONResponse(status_code=409, content={"error":"FREEZE_ID_CONFLICT"})
            return JSONResponse(content=FREEZES[fid]["response"])

        out=[freeze_candidate(c,d) for c in d["candidates"]]
        out.sort(key=lambda x:x["name"].encode("utf-8"))
        response={"freezeId":fid,"candidates":out}
        FREEZES[fid]={"fingerprint":fp,"response":response}
        return JSONResponse(content=response)

    # SELECT
    fid=d.get("freezeId")
    if not isinstance(fid,str) or not fid:
        return invalid_input()
    if not isinstance(d.get("candidates"),list) or not isinstance(d.get("rows"),list) or not isinstance(d.get("policy"),dict):
        return invalid_input()
    if not d["candidates"] or not d["rows"]:
        return invalid_input()

    p=d["policy"]
    if not select_policy_valid(p):
        return invalid_input()

    supplied=d["candidates"]
    order=p["candidateOrder"]
    names=[c.get("name") if isinstance(c,dict) else None for c in supplied]

    if any(not isinstance(n,str) or not n for n in names):
        return invalid_input()
    if len(names)!=len(set(names)) or set(names)!=set(order):
        return invalid_input()

    latencies=d.get("latencies")
    if not isinstance(latencies,dict):
        latencies={}

    stored=FREEZES.get(fid)
    stored_candidates=stored["response"]["candidates"] if stored else []
    stored_map={c["name"]:c for c in stored_candidates}

    # Supplied candidates must exactly equal the frozen response.
    exact=(supplied==stored_candidates)

    results=[]
    order_index={n:i for i,n in enumerate(order)}

    for name in order:
        rc=[]
        submitted=next(c for c in supplied if c.get("name")==name)
        frozen=stored_map.get(name)

        if frozen is None or not exact:
            rc.append("NOT_FROZEN")

        if frozen is None or frozen.get("status") not in ("frozen","unsupported"):
            rc.append("INVALID_LINEAGE")

        manifest_ok=valid_manifest(submitted)
        if not manifest_ok:
            rc.append("INVALID_MANIFEST")

        total=submitted.get("totalBytes") if manifest_ok else None
        if manifest_ok:
            inv=submitted["inventory"]
            total=sum(x["bytes"] for x in inv)
            if total != submitted["totalBytes"] or package_digest(inv)!=submitted["packageDigest"]:
                total=None
                if "INVALID_MANIFEST" not in rc:
                    rc.append("INVALID_MANIFEST")

        lat=latencies.get(name)
        if not finite_nonneg(lat):
            lat=None
            rc.append("INVALID_POLICY")

        agg=None
        slice_acc={}
        preds_valid=True
        slice_correct={}
        slice_total={}

        for row in d["rows"]:
            if not isinstance(row,dict) or "label" not in row or "slice" not in row or not isinstance(row.get("predictions"),dict):
                preds_valid=False
                break
            label=row["label"]
            pred=row["predictions"].get(name)
            if not prediction_binary(label) or not prediction_binary(pred):
                preds_valid=False
                break
            sl=row["slice"]
            if not isinstance(sl,str):
                preds_valid=False
                break
            slice_total[sl]=slice_total.get(sl,0)+1
            if pred==label:
                slice_correct[sl]=slice_correct.get(sl,0)+1

        if not preds_valid:
            rc.append("INVALID_PREDICTIONS")
        else:
            correct=0
            for row in d["rows"]:
                if row["predictions"][name] == row["label"]:
                    correct+=1
            agg=round(correct/len(d["rows"]),12)
            for sl in p["requiredSlices"]:
                if sl not in slice_total:
                    rc.append("MISSING_SLICE:"+sl)
                else:
                    slice_acc[sl]=round(slice_correct.get(sl,0)/slice_total[sl],12)

        if agg is not None and agg < p["aggregateFloor"]:
            rc.append("AGGREGATE_FLOOR")

        for sl,floor in p["requiredSlices"].items():
            if sl in slice_acc and slice_acc[sl] < floor:
                rc.append("SLICE_FLOOR:"+sl)

        if total is not None and total > p["maxBytes"]:
            rc.append("SIZE_LIMIT")
        if lat is not None and lat > p["maxLatencyMs"]:
            rc.append("LATENCY_LIMIT")

        rc=sort_codes(rc)
        results.append({
            "name":name,
            "aggregate":agg,
            "slices":slice_acc,
            "totalBytes":total,
            "latencyMs":lat,
            "admitted":len(rc)==0,
            "reasonCodes":rc
        })

    admitted=[r for r in results if r["admitted"]]
    if admitted:
        winner=min(admitted,key=lambda r:(r["totalBytes"],r["latencyMs"],order_index[r["name"]]))
        selected=winner["name"]
        package_manifest=stored_map[selected]
    else:
        selected=None
        package_manifest=None

    return JSONResponse(content={
        "freezeId":fid,
        "selected":selected,
        "results":results,
        "packageManifest":package_manifest
    })

if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=int(os.environ.get("PORT","8080")))
