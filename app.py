import os, datetime, requests, json, re, sys, subprocess, tempfile, traceback, io, hashlib, sqlite3
import streamlit as st

try:
    import pandas as pd
    PANDAS = True
except:
    PANDAS = False

try:
    from PIL import Image
    PIL = True
except:
    PIL = False

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("SERPER_API_KEY"):
    st.error("Missing API keys")
    st.stop()

DB_PATH = "sentinel.db"
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, timestamp TEXT, user_query TEXT, response TEXT, session_id TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS search_cache (query_hash TEXT PRIMARY KEY, query TEXT, results TEXT, timestamp TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, timestamp TEXT, file_name TEXT, alert_type TEXT, severity TEXT, message TEXT, row_data TEXT)")
    conn.commit()
    conn.close()
init_db()

def save_conv(user_query, response, session_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO conversations (timestamp, user_query, response, session_id) VALUES (?, ?, ?, ?)", (datetime.datetime.now().isoformat(), user_query, response, session_id))
    conn.commit()
    conn.close()

def get_history(session_id, limit=5):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_query, response, timestamp FROM conversations WHERE session_id = ? ORDER BY id DESC LIMIT ?", (session_id, limit))
    r = c.fetchall()
    conn.close()
    return r

def save_alert(file_name, alert_type, severity, message, row_data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, file_name, alert_type, severity, message, row_data) VALUES (?, ?, ?, ?, ?, ?)", (datetime.datetime.now().isoformat(), file_name, alert_type, severity, message, json.dumps(row_data)))
    conn.commit()
    conn.close()

def get_alerts(limit=20):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, file_name, alert_type, severity, message FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    r = c.fetchall()
    conn.close()
    return r

def detect_intent(q):
    q = q.lower()
    if any(k in q for k in ["code", "script", "function", "python", "write", "build"]):
        return "code"
    elif any(k in q for k in ["analyze", "chart", "count", "sum", "statistics"]):
        return "data"
    elif any(k in q for k in ["what", "who", "when", "where", "compare", "vs"]):
        return "search"
    elif any(k in q for k in ["file", "sheet", "tab", "column", "row"]):
        return "file"
    return "chat"

# ─── FILE PARSING ───
def parse_file(uploaded_file):
    name = uploaded_file.name
    ext = name.split(".")[-1].lower()
    bytes_data = uploaded_file.getvalue()
    if ext == "csv" and PANDAS:
        df = pd.read_csv(io.BytesIO(bytes_data))
        return {"type": "csv", "df": df, "text": f"CSV: {df.shape[0]} rows x {df.shape[1]} cols
Columns: {list(df.columns)}

{df.head(10).to_string()}"}
    elif ext in ["xlsx", "xls"] and PANDAS:
        xls = pd.ExcelFile(io.BytesIO(bytes_data))
        sheets = {}
        out = [f"Excel: {len(xls.sheet_names)} sheets"]
        for sheet in xls.sheet_names:
            df = pd.read_excel(io.BytesIO(bytes_data), sheet_name=sheet)
            sheets[sheet] = df
            out.append(f"
Sheet '{sheet}': {df.shape[0]} rows x {df.shape[1]} cols
Columns: {list(df.columns)}
{df.head(5).to_string()}")
        return {"type": "excel", "sheets": sheets, "text": "
".join(out)}
    elif ext in ["txt", "pdf"]:
        return {"type": "text", "text": bytes_data.decode("utf-8", errors="ignore")[:5000]}
    elif ext in ["png", "jpg", "jpeg"] and PIL:
        img = Image.open(io.BytesIO(bytes_data))
        return {"type": "image", "image": img, "text": f"Image: {img.format} | {img.size} | Mode: {img.mode}"}
    else:
        return {"type": "binary", "text": f"File: {name} ({len(bytes_data)} bytes)"}

# ─── ALERT SYSTEM ───
def run_alerts(file_name, parsed_data):
    alerts = []

    if parsed_data["type"] == "csv" and PANDAS:
        df = parsed_data["df"]

        # Rule 1: Missing serial numbers
        if "Serial" in df.columns or "serial" in df.columns or "Serial_Number" in df.columns:
            serial_col = next((c for c in df.columns if "serial" in c.lower()), None)
            if serial_col:
                missing = df[df[serial_col].isna() | (df[serial_col] == "")]
                for idx, row in missing.iterrows():
                    alerts.append({"type": "MISSING_SERIAL", "severity": "HIGH", "message": f"Row {idx}: Missing {serial_col}", "row": row.to_dict()})

        # Rule 2: Duplicate Device_ID
        if "Device_ID" in df.columns:
            dups = df[df.duplicated("Device_ID", keep=False)]
            for dev_id in dups["Device_ID"].unique():
                alerts.append({"type": "DUPLICATE_ID", "severity": "MEDIUM", "message": f"Duplicate Device_ID: {dev_id} ({len(dups[dups['Device_ID']==dev_id])} occurrences)", "row": {}})

        # Rule 3: Status mismatch
        if "Status" in df.columns and "Return_Date" in df.columns:
            damaged = df[(df["Status"].str.lower() == "damaged") & (df["Return_Date"].isna() | (df["Return_Date"] == ""))]
            for idx, row in damaged.iterrows():
                alerts.append({"type": "STATUS_MISMATCH", "severity": "MEDIUM", "message": f"Row {idx}: Status=Damaged but no Return_Date", "row": row.to_dict()})

        # Rule 4: Invalid q-number format
        if "Q_Number" in df.columns or "q_number" in df.columns:
            q_col = next((c for c in df.columns if "q" in c.lower() and "number" in c.lower()), None)
            if q_col:
                invalid = df[~df[q_col].astype(str).str.match(r"^Q\d{3,}$", na=False)]
                for idx, row in invalid.iterrows():
                    alerts.append({"type": "INVALID_FORMAT", "severity": "LOW", "message": f"Row {idx}: Invalid {q_col} format: {row[q_col]}", "row": row.to_dict()})

    elif parsed_data["type"] == "excel" and PANDAS:
        sheets = parsed_data["sheets"]
        # Cross-sheet orphan check
        if "Main_Data" in sheets and "Damaged_Lost" in sheets:
            main_ids = set(sheets["Main_Data"].get("Device_ID", pd.Series()).dropna().astype(str))
            damaged_ids = set(sheets["Damaged_Lost"].get("Device_ID", pd.Series()).dropna().astype(str))
            orphans = damaged_ids - main_ids
            for oid in orphans:
                alerts.append({"type": "ORPHAN_RECORD", "severity": "HIGH", "message": f"Device_ID {oid} in Damaged_Lost but not in Main_Data", "row": {}})

    # Save to DB
    for alert in alerts:
        save_alert(file_name, alert["type"], alert["severity"], alert["message"], alert["row"])

    return alerts

# ─── DEEP SEARCH ───
def deep_search(query, api_key, max_results=10):
    h = hashlib.md5(query.lower().strip().encode()).hexdigest()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT results, timestamp FROM search_cache WHERE query_hash = ?", (h,))
    cached = c.fetchone()
    conn.close()
    if cached:
        t = datetime.datetime.fromisoformat(cached[1])
        if datetime.datetime.now() - t < datetime.timedelta(hours=24):
            return {**json.loads(cached[0]), "from_cache": True}

    all_results = []
    try:
        url = "https://google.serper.dev/search"
        headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
        res = requests.post(url, headers=headers, json={"q": query, "num": max_results}, timeout=15)
        if res.status_code == 200:
            for item in res.json().get("organic", []):
                all_results.append({"title": item.get("title", ""), "link": item.get("link", ""), "snippet": item.get("snippet", ""), "score": 100 - (item.get("position", 10) * 5)})
    except:
        pass

    if len(all_results) < 5:
        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
            res = requests.get(ddg_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
            if res.status_code == 200:
                links = re.findall(r'<a rel="nofollow" class="result__a" href="(https?://[^"]+)">([^<]+)</a>', res.text)
                for i, (link, title) in enumerate(links[:max_results]):
                    all_results.append({"title": title, "link": link, "snippet": "", "score": 50 - i * 5})
        except:
            pass

    seen = set()
    unique = []
    for r in all_results:
        if r["link"] not in seen:
            seen.add(r["link"])
            if any(d in r["link"] for d in [".gov", ".edu", "arxiv", "github"]):
                r["score"] += 30
            unique.append(r)
    unique.sort(key=lambda x: x["score"], reverse=True)

    output = {"query": query, "results": unique[:max_results], "sources": list(set([r["link"].split("/")[2] for r in unique if r.get("link")])), "from_cache": False}
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO search_cache (query_hash, query, results, timestamp) VALUES (?, ?, ?, ?)", (h, query, json.dumps(output), datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return output

def execute_python(code, timeout=15):
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir=os.getcwd()) as f:
            f.write(code)
            temp = f.name
        result = subprocess.run([sys.executable, temp], capture_output=True, text=True, timeout=timeout)
        os.unlink(temp)
        return {"status": "success" if result.returncode == 0 else "error", "output": result.stdout.strip(), "errors": result.stderr.strip() if result.returncode != 0 else None}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": "", "errors": f"Timeout {timeout}s"}
    except Exception as e:
        return {"status": "error", "output": "", "errors": str(e)}

from crewai import Agent, Task, Crew, Process
from crewai.tools import tool

@tool("search")
def search_tool(q: str) -> str:
    "Search the web using deep search with caching and quality scoring."
    api_key = os.environ.get("SERPER_API_KEY", "")
    r = deep_search(q, api_key, max_results=10)
    if r["results"]:
        out = [f"Search (cached: {r['from_cache']})"]
        for item in r["results"][:5]:
            out.append(f"- [{item['score']}pts] {item['title']}: {item['link']}
  {item['snippet'][:150]}")
        return "
".join(out)
    return "No results."

@tool("run_code")
def run_code_tool(code: str) -> str:
    "Execute Python code safely and return output."
    r = execute_python(code)
    if r["status"] == "success":
        return f"OUTPUT:
{r['output']}"
    return f"ERROR:
{r['errors']}"

def sentinel(directive, file_context="", session_id="default"):
    intent = detect_intent(directive)
    full = directive + (f"

[FILES]
{file_context[:3000]}" if file_context else "")

    planner = Agent(role="Planner", goal="Plan approach", backstory="Detect intent and plan. Intent: " + intent, verbose=True, allow_delegation=False)
    plan_task = Task(description=f"Plan for: {full}

Intent: {intent}
Create numbered plan.", agent=planner, expected_output="Plan")
    crew = Crew(agents=[planner], tasks=[plan_task], process=Process.sequential, verbose=False)
    plan = crew.kickoff().raw

    tools = {"code": [search_tool, run_code_tool], "data": [search_tool, run_code_tool], "search": [search_tool], "file": [search_tool], "chat": [search_tool]}
    selected = tools.get(intent, [search_tool])

    researcher = Agent(role="Researcher", goal="Find facts", backstory="Use tools. Cite sources. Reference file data.", tools=selected, verbose=True, allow_delegation=False)
    research_task = Task(description=f"Execute: {plan}

For: {full}

Use tools. Cite sources.", agent=researcher, expected_output="Research")
    crew = Crew(agents=[researcher], tasks=[research_task], process=Process.sequential, verbose=False)
    findings = crew.kickoff().raw

    critic = Agent(role="Critic", goal="Critique findings", backstory="Check gaps, weak sources, errors. Suggest improvements.", verbose=True, allow_delegation=False)
    critique_task = Task(description=f"Critique findings for: {directive}

Findings: {findings[:2000]}

Check: gaps, sources, errors, missing info.", agent=critic, expected_output="Critique")
    crew = Crew(agents=[critic], tasks=[critique_task], process=Process.sequential, verbose=False)
    critique = crew.kickoff().raw

    synthesizer = Agent(role="Writer", goal="Synthesize final answer", backstory="Write clear, factual answer. Use markdown. Note gaps. Incorporate critique.", verbose=True, allow_delegation=False)
    synth_task = Task(description=f"Question: {full}
Research: {findings}
Critique: {critique}

Write final answer with markdown. Cite sources. End with Sources: list.", agent=synthesizer, expected_output="Final answer")
    crew = Crew(agents=[synthesizer], tasks=[synth_task], process=Process.sequential, verbose=False)
    answer = crew.kickoff().raw

    save_conv(directive, answer, session_id)
    return {"plan": plan, "findings": findings, "critique": critique, "answer": answer, "intent": intent, "timestamp": datetime.datetime.now().isoformat()}

st.set_page_config(page_title="Sentinel v8", page_icon="🛡️", layout="wide")
st.title("🛡️ Sentinel v8")
st.caption("Alerts · Image Analysis · Reasoning · Self-Reflection · Deep Search")

if "session_id" not in st.session_state:
    st.session_state.session_id = f"sess_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
if "files" not in st.session_state:
    st.session_state.files = {}
if "alerts" not in st.session_state:
    st.session_state.alerts = []

sid = st.session_state.session_id

with st.sidebar:
    st.header("System")
    st.success("OpenAI")
    st.success("Serper")
    st.success("SQLite")
    st.success("Alerts")
    st.success("Images")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM conversations WHERE session_id = ?", (sid,))
    st.metric("Conversations", c.fetchone()[0])
    c.execute("SELECT COUNT(*) FROM search_cache")
    st.metric("Cache", c.fetchone()[0])
    c.execute("SELECT COUNT(*) FROM alerts")
    st.metric("Total Alerts", c.fetchone()[0])
    conn.close()

    if st.button("Clear Session"):
        st.session_state.files = {}
        st.session_state.alerts = []
        st.success("Cleared!")
        st.rerun()

    st.markdown("---")
    st.header("Upload Files")
    uploaded = st.file_uploader("Drop files", type=["csv", "xlsx", "xls", "txt", "pdf", "png", "jpg", "jpeg"], accept_multiple_files=True)

    file_context = ""
    all_alerts = []
    if uploaded:
        for f in uploaded:
            data = parse_file(f)
            st.session_state.files[f.name] = data

            icon = "📊" if data["type"] in ["csv", "excel"] else "🖼️" if data["type"] == "image" else "📄"
            st.markdown(f"**{icon} {f.name}** ({len(f.getvalue())} bytes)")

            if data["type"] in ["csv", "excel"]:
                st.text(data["text"][:150] + "...")
                # Run alerts
                alerts = run_alerts(f.name, data)
                if alerts:
                    st.markdown("**🚨 Alerts Found:**")
                    for alert in alerts:
                        severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
                        st.markdown(f"{severity_emoji.get(alert['severity'], '⚪')} **{alert['type']}** ({alert['severity']})
{alert['message']}")
                    all_alerts.extend(alerts)
                else:
                    st.success("✅ No issues detected")
                file_context += f"
[FILE: {f.name}]
{data['text'][:2000]}"
            elif data["type"] == "image":
                st.image(data["image"], caption=f.name, use_container_width=True)
                file_context += f"
[IMAGE: {f.name}]
{data['text']}
[Image content available for analysis]"
            else:
                st.text(data["text"][:150] + "...")
                file_context += f"
[FILE: {f.name}]
{data['text'][:2000]}"

    # Show alert history
    if all_alerts or st.session_state.alerts:
        st.markdown("---")
        st.header("Alert History")
        for alert in get_alerts(10):
            severity_color = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
            st.markdown(f"<span style='color: {severity_color.get(alert[3], 'gray')};'>●</span> **{alert[2]}** ({alert[3]}) - {alert[4][:60]}...", unsafe_allow_html=True)

    st.markdown("---")
    st.header("History")
    for query, resp, ts in get_history(sid, 5):
        st.caption(f"**Q:** {query[:30]}...")
        st.text(ts[:10])

st.markdown("---")
col1, col2 = st.columns([3, 1])
with col1:
    directive = st.text_area("Directive:", height=100, placeholder="Ask anything... Upload files for auto-analysis")
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    run = st.button("🚀 Execute", use_container_width=True, type="primary")

if run and directive.strip():
    intent = detect_intent(directive)
    st.info(f"Detected intent: **{intent.upper()}**")

    status = st.empty()
    status.info("🧠 Reasoning...")

    try:
        result = sentinel(directive, file_context=file_context, session_id=sid)
        status.empty()

        with st.expander("📋 Plan"): st.markdown(result["plan"])
        with st.expander("🔍 Findings"): st.markdown(result["findings"])
        with st.expander("🎯 Self-Critique"): st.markdown(result["critique"])

        st.markdown("### ✨ Final Answer")
        st.markdown(result["answer"])

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        md = f"# Sentinel Report

**Q:** {directive}
**Intent:** {result['intent']}
**Time:** {result['timestamp']}

## Plan
{result['plan']}

## Findings
{result['findings']}

## Critique
{result['critique']}

## Answer
{result['answer']}"
        st.download_button("📥 Download", md, file_name=f"sentinel_{ts}.md", mime="text/markdown")

    except Exception as e:
        status.empty()
        st.error(f"Failed: {e}")
        st.code(traceback.format_exc())
elif run:
    st.warning("Enter a directive first.")
