import sys, time
sys.path.insert(0,'.')
import cfgweb as W, cfgscan
def mk(raw, sites, alive=True, lat=100):
    return {"raw":raw,"host":raw,"port":1,"flags":set(),"sites":sites,"alive":alive,"success":1.0,"lat":lat,"jitter":0,"proto":"vless","network":"tcp","security":"tls","reachable":True,"verified_at":time.time()}
F=dict(yt=1,ig=1,tg=1); YI=dict(yt=1,ig=1,tg=0); TG=dict(yt=0,ig=0,tg=1); YT=dict(yt=1,ig=0,tg=0)
# --- strict acceptance
W.TGONLY[0]=False
assert W.sites_ok({"sites":F}) and not W.sites_ok({"sites":YI}) and not W.sites_ok({"sites":TG}) and not W.sites_ok({"sites":YT})
W.TGONLY[0]=True
assert W.sites_ok({"sites":TG}) and W.sites_ok({"sites":F}) and not W.sites_ok({"sites":YI})
W.TGONLY[0]=False
print("acceptance OK")
# --- sites_pick: never returns tg-only / yt+ig-only in strict mode, even if they are the only ones
table={"A":mk("A",TG),"B":mk("B",YI),"C":mk("C",YT),"D":mk("D",F,lat=300),"E":mk("E",F,lat=50),"X":mk("X",{},alive=False)}
W.check=lambda c,*a,**k:dict(table[c["raw"]])  # sites_pick حالا هر سرور رو جدا (موازی) می‌سنجه
W.danger=lambda c: False
found=[mk(k,{}) for k in "ABC"]
cache={}
pool=W.sites_pick(found,cache)
print("only partial servers found ->",[r["raw"] for r in pool],"| tiers",W.site_tiers(cache))
assert pool==[]
t=W.site_tiers(cache); assert t["ytig"]==1 and t["tg"]==1 and t["full"]==0
found+= [mk("D",{}),mk("E",{}),mk("X",{})]
pool=W.sites_pick(found,cache,first_ok=False)  # ترتیبِ کاملِ نتیجه رو می‌خوایم، نه خروجِ زودهنگام
print("after full ones appear ->",[r["raw"] for r in pool]); assert [r["raw"] for r in pool]==["E","D"]
# tg-only mode accepts tg servers (and full), best score first
W.TGONLY[0]=True
pool=W.sites_pick(found,cache,first_ok=False); print("tg-only mode ->",[r["raw"] for r in pool]); assert {r["raw"] for r in pool}=={"A","D","E"} and pool[0]["raw"] in ("D","E")
W.TGONLY[0]=False
# --- retry of failed results after 4 minutes
calls=[0]
def counting(c,*a,**k):
    calls[0]+=1; return dict(table[c["raw"]])
W.check=counting
cache2={}; f2=[mk("B",{})]
W.sites_pick(f2,cache2); W.sites_pick(f2,cache2); assert calls[0]==1       # not retested right away
cache2["B"]["site_t"]-=300; W.sites_pick(f2,cache2); assert calls[0]==2     # retested after 4+ min
print("retry window OK")
# --- save_settings
W.save_settings({"tgonly":True}); assert W.TGONLY[0] is True; W.save_settings({"tgonly":False}); assert W.TGONLY[0] is False
W.save_settings({"tgonly":"yes"}); assert W.TGONLY[0] is False
print("settings OK")
# --- guard: strict never settles for tg-only / yt+ig
W.POOL.update(active=[mk("A",TG)],standby=[],backlog=[],switches=0)
W.GEN[0]=1; W.STOP.clear()
clock=[1000.0]; time.time=lambda: clock[0]; time.sleep=lambda x: clock.__setitem__(0,clock[0]+x)
cfgscan.site_check=lambda port,t: TG
cfgscan.reach=lambda c,t: None
W.check=lambda c,*a,**k:dict(table[c["raw"]])  # sites_pick حالا هر سرور رو جدا (موازی) می‌سنجه
started=[]; W.start_xray=lambda sel,p:(started.append(sel[0]["raw"]) or sel); W.probe_retry=lambda *a,**k:40
W.set_active=lambda sel,ms: W.POOL.update(active=sel); W.save_good=lambda s:None
W.sites_guard(1,"balanced",[mk("B",{}),mk("C",{}),mk("A",{})])
print("guard with only partial servers ->",started,"| note:",W.S["note"][:70]); assert started==[]
W.POOL.update(active=[mk("A",TG)],standby=[],backlog=[],switches=0)
W.sites_guard(1,"balanced",[mk("B",{}),mk("D",{}),mk("E",{})])
print("guard with a full server ->",started,"| note:",W.S["note"]); assert started and started[0] in ("D","E")
print("ALL OK")
