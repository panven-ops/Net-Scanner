import { useState } from "react";
import "./App.css";


const API_BASE = "http://localhost:8000";

// PORT_INFO: εξηγήσεις για κάθε γνωστό port.

const PORT_INFO = {
  21:   { desc: "FTP — μεταφορά αρχείων. Στέλνει username/password χωρίς κρυπτογράφηση.", tip: "Χρησιμοποίησε SFTP ή SCP αντί για FTP." },
  22:   { desc: "SSH — ασφαλής απομακρυσμένη πρόσβαση. Κρυπτογραφημένο, αλλά συχνός στόχος brute-force.", tip: "Χρησιμοποίησε SSH keys αντί για password. Σκέψου fail2ban." },
  23:   { desc: "Telnet — παλιό πρωτόκολλο remote access. Όλα τα δεδομένα (passwords!) πάνε plaintext.", tip: "Κλείσε το αμέσως. Αντικατάστησε με SSH." },
  25:   { desc: "SMTP — αποστολή email. Αν είναι ανοιχτό δημόσια, μπορεί να χρησιμοποιηθεί για spam relay.", tip: "Περιόρισε πρόσβαση μόνο σε trusted IPs." },
  80:   { desc: "HTTP — web server χωρίς κρυπτογράφηση. Τα δεδομένα φαίνονται plaintext.", tip: "Redirect σε HTTPS (port 443)." },
  443:  { desc: "HTTPS — κρυπτογραφημένος web server με TLS/SSL. Το standard για web traffic.", tip: "Βεβαιώσου ότι το certificate είναι ενημερωμένο." },
  631:  {desc:  "IPP - linux print server, τρέχει σχεδόν σε κάθε Linux εγκατάσταση. Είναι ακίνδυνο όταν είναι τοπικά."},
  3306: { desc: "MySQL database. Δεν πρέπει ποτέ να είναι εκτεθειμένο στο internet.", tip: "Bind μόνο σε localhost (127.0.0.1) στο my.cnf." },
  5432: { desc: "PostgreSQL database. Ίδιο πρόβλημα με MySQL αν είναι δημόσια ανοιχτό.", tip: "Χρησιμοποίησε pg_hba.conf για να περιορίσεις πρόσβαση." },
  6379: { desc: "Redis — in-memory database. Από default δεν έχει authentication!", tip: "Βάλε requirepass στο redis.conf και bind μόνο localhost." },
  8080: { desc: "HTTP alternative — συχνά dev server ή proxy. Εξαρτάται τι τρέχει πίσω.", tip: "Βεβαιώσου ότι δεν τρέχει development server σε production." },
};

// VERDICT_CONFIG: χρώματα + εικονίδια για κάθε verdict.

const VERDICT_CONFIG = {
  safe:       { icon: "✓", label: "SAFE"      },
  suspicious: { icon: "⚠", label: "SUSPICIOUS" },
  dangerous:  { icon: "✕", label: "DANGEROUS"  },
  unknown:    { icon: "?", label: "UNKNOWN"    },
};


// COMPONENT: RiskBadge

function RiskBadge({ risk }) {
  return (
    <span className={`risk-badge risk-badge--${risk}`}>
      {risk}
    </span>
  );
}

// COMPONENT: VerdictBanner

function VerdictBanner({ verdict, score }) {
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.unknown;

  return (
    <div className={`verdict verdict--${verdict ?? "unknown"}`}>
      <div className="verdict__left">
        {}
        <span className="verdict__icon">{cfg.icon}</span>
        <div>
          <div className="verdict__label-hint">verdict</div>
          <div className="verdict__label">{cfg.label}</div>
        </div>
      </div>
      {}
      <div>
        <div className="verdict__score-hint">risk score</div>
        <div className="verdict__score">{score}</div>
      </div>
    </div>
  );
}

// COMPONENT: HostInfo

function HostInfo({ result }) {
  const cards = [
    { label: "target", value: result.target },
    { label: "ip",     value: result.ip },
    { label: "status", value: result.is_up ? "up" : "down" },
  ];

  return (
    <div className="host-info">
      {cards.map(({ label, value }) => (
        <div key={label} className="host-info__card">
          <div className="host-info__label">{label}</div>
          <div className="host-info__value">{value}</div>
        </div>
      ))}
    </div>
  );
}

// COMPONENT: PortsTable

function PortsTable({ ports }) {

  const [expandedPort, setExpandedPort] = useState(null);

  if (!ports || ports.length === 0) {
    return <div className="scanner__warning">no open ports found</div>;
  }

  function handleRowClick(port) {

    setExpandedPort(prev => prev === port ? null : port);
  }

  return (
    <div className="ports-table-wrap">
      <table className="ports-table">
        <thead>
          <tr>
            {}
            {["port", "state", "service", "risk", "info"].map(h => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ports.map((p) => {

            const isExpanded = expandedPort === p.port;
            const info = PORT_INFO[p.port];

            return (

              <>
                {}
                <tr
                  key={p.port}
                  onClick={() => handleRowClick(p.port)}
                  title="click for details"
                >
                  <td className="col-port">{p.port}</td>
                  <td className="col-state">{p.state}</td>
                  <td>{p.service}</td>
                  <td><RiskBadge risk={p.risk} /></td>
                  {}
                  <td className="col-state">{isExpanded ? "▲" : "▼"}</td>
                </tr>

                {}
                {isExpanded && (
                  <tr className="row-desc" key={`${p.port}-desc`}>
                    {}
                    <td colSpan={5}>
                      <div className="port-desc">
                        {info ? (
                          <>
                            {}
                            <span className="port-desc__label">what:</span>
                            {info.desc}
                            <br />
                            {}
                            <span className="port-desc__label">tip:</span>
                            {info.tip}
                          </>
                        ) : (
                          <span>port {p.port} — no additional information available</span>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// COMPONENT: ScanHistory

function ScanHistory({ history, onSelect }) {
  if (history.length === 0) return null;

  return (
    <div className="history">
      <div className="history__title">recent scans</div>
      <ul className="history__list">
        {history.map((item) => (
          <li
            key={item.id}
            className="history__item"
            onClick={() => onSelect(item)}
          >
            <div className="history__item-left">
              {}
              <span className={`history__dot history__dot--${item.result.verdict}`} />
              <span className="history__target">{item.result.target}</span>
            </div>
            <div className="history__item-right">
              {}
              <span>{item.time}</span>
              <span className="history__score">score: {item.result.total_score}</span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

// COMPONENT: NetworkScanner (το κύριο / root component)

export default function NetworkScanner() {
  const [target, setTarget] = useState("");


  const [status, setStatus] = useState("idle");

  const [result, setResult] = useState(null);

  const [errMsg, setErrMsg] = useState("");


  const [history, setHistory] = useState([]);


  async function handleScan() {
    const t = target.trim();
    if (!t) return;

    setStatus("loading");
    setResult(null);
    setErrMsg("");

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail ?? `HTTP ${res.status}`);
      }

      const data = await res.json();

      setResult(data);
      setStatus("done");

      if (!data.error) {
        setHistory(prev => [
          {
            id: Date.now(),
            time: new Date().toLocaleTimeString(),
            result: data,
          },
          ...prev.slice(0, 9),
        ]);
      }

    } catch (e) {
      setErrMsg(e.message ?? "Request failed");
      setStatus("error");
    }
  }

  function handleKey(e) {
    if (e.key === "Enter") handleScan();
  }

  function handleHistorySelect(item) {
    setResult(item.result);
    setTarget(item.result.target);
    setStatus("done");
  }


  return (
    <div className="scanner">

      {}
      <div className="scanner__header">
        <h1 className="scanner__title">network scanner</h1>
        <p className="scanner__subtitle">
          scan open ports and assess exposure risk using nmap
        </p>
      </div>

      {}
      <div className="scanner__input-row">
        <input
          className="scanner__input"
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={handleKey}
          placeholder="scanme.nmap.org or 192.168.1.1"
          disabled={status === "loading"}
        />
        <button
          className="scanner__btn"
          onClick={handleScan}
          disabled={status === "loading" || !target.trim()}
        >
          {}
          {status === "loading" ? "scanning…" : "scan →"}
        </button>
      </div>

      {}
      {status === "loading" && (
        <div className="scanner__loading">
          <span className="scanner__loading-icon">⟳</span>
          running nmap scan on <strong>{target}</strong>…
          <div className="scanner__loading-hint">this can take up to 2 minutes</div>
        </div>
      )}

      {}
      {status === "error" && (
        <div className="scanner__error">
          error: {errMsg}
        </div>
      )}

      {}
      {status === "done" && result && (
        <div>
          {}
          {result.error && (
            <div className="scanner__warning">{result.error}</div>
          )}

          {}
          {!result.error && (
            <>
              <VerdictBanner verdict={result.verdict} score={result.total_score} />
              <HostInfo result={result} />
              <div className="ports-header">
                open ports ({result.ports.length})
              </div>
              <PortsTable ports={result.ports} />
            </>
          )}
        </div>
      )}

      {}
      <ScanHistory history={history} onSelect={handleHistorySelect} />

    </div>
  );
}
