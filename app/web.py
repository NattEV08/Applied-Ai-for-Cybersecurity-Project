"""Minimal read-only localhost dashboard. Auth is NOT yet implemented."""
from flask import Flask,jsonify,render_template_string
from app.db import initialize,fetch,find_one
from app.risk import add_priority
from app.llm import explain

app=Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=1024*1024
TEMPLATE="""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IT2527 — Vulnerability Analyst</title><style>
body{background:#101722;color:#e9edf4;font:15px system-ui;margin:0;padding:32px;line-height:1.5}
main{max-width:1060px;margin:auto} h1{font-size:30px} p{color:#b7c4d9}table{border-collapse:collapse;width:100%;background:#192334}
th,td{padding:11px;border-bottom:1px solid #364052;text-align:left;vertical-align:top}
th{color:#9fd2fe;font-weight:600}small{color:#b7c4d9}.box{padding:14px;background:#263649;border-left:3px solid #7bb6ff;margin:16px 0}
</style></head><body><main><h1>Retail vulnerability review</h1>
<p>Local Proof-of-Concept · Evidence from SAST/SCA · Deterministic risk score (not CVSS)</p>
<div class="box">Week 4 starter: synthetic fixtures. The local AI is optional, no auto-remediation or external cloud inference. No authentication yet: do not expose to a network.</div>
<table><thead><tr><th>Asset / stakeholder</th><th>Source</th><th>Finding</th><th>Evidence</th><th>Risk</th></tr></thead><tbody>
{% for x in findings %}<tr><td>{{x.asset_name}}<br><small>{{x.stakeholder}}</small></td>
<td>{{x.scanner}}</td><td>{{x.finding_id}}</td>
<td>{{x.package or x.cwe_id or 'N/A'}}<br><small>{{x.file_path}}</small></td>
<td>{{x.priority_label}} ({{x.priority_score}})<br><small>{{x.score_basis}}</small></td></tr>{% endfor %}
</tbody></table><p><small>API: GET /api/findings; POST /api/analyze/&lt;id&gt; (requires installed local Ollama).</small></p></main></body></html>"""

@app.get('/')
def index():
    rows=sorted((add_priority(x) for x in fetch()),key=lambda x:x['priority_score'],reverse=True)
    return render_template_string(TEMPLATE,findings=rows)

@app.get('/api/findings')
def findings():
    return jsonify(sorted((add_priority(x) for x in fetch()),key=lambda x:x['priority_score'],reverse=True))

@app.post('/api/analyze/<int:finding_id>')
def analyze(finding_id):
    f=find_one(finding_id)
    if not f: return jsonify({'error':'Finding not found'}),404
    try: output=explain(add_priority(f))
    except Exception as exc:
        return jsonify({'error':'Local model not available or response invalid','detail':str(exc)[:200]}),503
    return jsonify({'finding_id':finding_id,'analysis':output,'human_review_required':True})

if __name__=='__main__':
    initialize()
    app.run(host='127.0.0.1',port=5000,debug=False)
