import { useEffect, useState } from "react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import "./App.css";

const API_URL = "https://port-scanner-1-atiz.onrender.com";

function App() {
  // ============================================================
  // AUTH
  // ============================================================

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authMode, setAuthMode] = useState("login");

  const [token, setToken] = useState(
    localStorage.getItem("access_token") || ""
  );

  const [loggedInUser, setLoggedInUser] = useState(
    localStorage.getItem("username") || ""
  );

  // ============================================================
  // NAVIGATION
  // ============================================================

  const [activePage, setActivePage] = useState("dashboard");

  // ============================================================
  // SCAN
  // ============================================================

  const [target, setTarget] = useState("");
  const [results, setResults] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [scanDuration, setScanDuration] = useState("");

  // ============================================================
  // SCAN OPTIONS
  // ============================================================

  const [showScanOptions, setShowScanOptions] = useState(false);

  const [selectedOptions, setSelectedOptions] = useState([
    "tcp"
  ]);

  const scanOptions = [
    {
      id: "tcp",
      icon: "◉",
      label: "TCP Scan",
      description: "Standard TCP port discovery"
    },
    {
      id: "udp",
      icon: "◌",
      label: "UDP Scan",
      description: "Discover UDP services"
    },
    {
      id: "syn",
      icon: "◈",
      label: "SYN Scan",
      description: "Fast stealth scanning"
    },
    {
      id: "service",
      icon: "⚙",
      label: "Service Detection",
      description: "Detect service versions"
    },
    {
      id: "os",
      icon: "◐",
      label: "OS Detection",
      description: "Identify operating system"
    },
    {
      id: "aggressive",
      icon: "⚡",
      label: "Aggressive Scan",
      description: "Advanced deep scanning"
    }
  ];

  // ============================================================
  // EMAIL
  // ============================================================

  const [recipientEmail, setRecipientEmail] = useState("");

  // ============================================================
  // HELPERS
  // ============================================================

  const getToken = () => {
    return localStorage.getItem("access_token") || token;
  };

  const authHeaders = () => {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`
    };
  };

  const getRiskClass = (risk) => {
    const value = String(risk || "unknown").toLowerCase();

    if (value.includes("high") || value.includes("critical")) {
      return "high";
    }

    if (value.includes("medium")) {
      return "medium";
    }

    if (value.includes("low")) {
      return "low";
    }

    return "unknown";
  };

  // ============================================================
  // DASHBOARD CALCULATIONS
  // ============================================================

  const highRiskCount = results.filter((item) => {
    const risk = String(item.risk || "").toLowerCase();

    return risk.includes("high") || risk.includes("critical");
  }).length;

  const mediumRiskCount = results.filter((item) =>
    String(item.risk || "").toLowerCase().includes("medium")
  ).length;

  const lowRiskCount = results.filter((item) =>
    String(item.risk || "").toLowerCase().includes("low")
  ).length;

  const openPortsCount = results.filter((item) =>
    String(item.state || "").toLowerCase().includes("open")
  ).length;

  // ============================================================
  // TOGGLE SCAN OPTION
  // ============================================================

  const toggleScanOption = (optionId) => {
    setSelectedOptions((previousOptions) => {
      if (previousOptions.includes(optionId)) {
        return previousOptions.filter(
          (item) => item !== optionId
        );
      }

      return [...previousOptions, optionId];
    });
  };

  // ============================================================
  // LOAD HISTORY
  // ============================================================

  useEffect(() => {
    if (token) {
      loadHistory();
    }
  }, [token]);

  const loadHistory = async () => {
    try {
      const currentToken = getToken();

      if (!currentToken) {
        return;
      }

      const response = await fetch(
        `${API_URL}/history`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${currentToken}`
          }
        }
      );

      if (
        response.status === 401 ||
        response.status === 422
      ) {
        handleLogout();
        return;
      }

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.error || "Failed to load scan history."
        );
        return;
      }

      setHistory(data.history || []);
    } catch (error) {
      console.error("History error:", error);
    }
  };

  // ============================================================
  // LOGIN / REGISTER
  // ============================================================

  const handleAuth = async (e) => {
    e.preventDefault();

    setMessage("");

    const endpoint =
      authMode === "login"
        ? "/login"
        : "/register";

    try {
      const response = await fetch(
        `${API_URL}${endpoint}`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            username,
            password
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.error || "Authentication failed."
        );
        return;
      }

      if (authMode === "register") {
        setMessage(
          "Registration successful. Please login."
        );

        setAuthMode("login");
        setPassword("");

        return;
      }

      localStorage.setItem(
        "access_token",
        data.access_token
      );

      localStorage.setItem(
        "username",
        data.username
      );

      setToken(data.access_token);
      setLoggedInUser(data.username);

      setUsername("");
      setPassword("");

      setMessage("");
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to connect to backend."
      );
    }
  };

  // ============================================================
  // LOGOUT
  // ============================================================

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("username");

    setToken("");
    setLoggedInUser("");

    setResults([]);
    setTarget("");
    setHistory([]);
    setScanDuration("");

    setRecipientEmail("");
    setSelectedOptions(["tcp"]);

    setActivePage("dashboard");

    setShowScanOptions(false);
    setLoading(false);
  };

  // ============================================================
  // SCAN TARGET
  // ============================================================

  const scanTarget = async () => {
    if (!target.trim()) {
      setMessage(
        "Please enter an IP address or domain."
      );
      return;
    }

    if (selectedOptions.length === 0) {
      setMessage(
        "Please select at least one scan option."
      );
      return;
    }

    const currentToken = getToken();

    if (!currentToken) {
      setMessage(
        "Please login before scanning."
      );
      return;
    }

    setLoading(true);
    setMessage("");

    setResults([]);
    setScanDuration("");

    setShowScanOptions(false);

    try {
      const response = await fetch(
        `${API_URL}/scan`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${currentToken}`
          },

          body: JSON.stringify({
            target: target.trim(),
            scan_options: selectedOptions
          })
        }
      );

      if (
        response.status === 401 ||
        response.status === 422
      ) {
        handleLogout();

        setMessage(
          "Session expired. Please login again."
        );

        return;
      }

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.details ||
          data.error ||
          "Scan failed."
        );

        return;
      }

      const scanResults = data.results || [];

      setResults(scanResults);

      setScanDuration(
        data.scan_duration ?? "-"
      );

      await loadHistory();

      setActivePage("results");

      setMessage(
        `Scan completed. ${scanResults.length} service(s) discovered.`
      );
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to connect to backend."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // LOAD HISTORY ITEM
  // ============================================================

  const loadHistoryItem = (item) => {
    setTarget(item.target || "");

    let savedResults = item.results || [];

    if (typeof savedResults === "string") {
      try {
        savedResults = JSON.parse(savedResults);
      } catch {
        savedResults = [];
      }
    }

    setResults(savedResults);

    setScanDuration(
      item.scan_duration ?? ""
    );

    setActivePage("results");

    setMessage("Previous scan loaded.");
  };

  // ============================================================
  // DELETE HISTORY ITEM
  // ============================================================

  const deleteHistoryItem = async (item) => {
    const confirmDelete = window.confirm(
      "Delete this scan history?"
    );

    if (!confirmDelete) return;

    try {
      const currentToken = getToken();

      const response = await fetch(
        `${API_URL}/history/${item.id}`,
        {
          method: "DELETE",

          headers: {
            Authorization:
              `Bearer ${currentToken}`
          }
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.error ||
          "Failed to delete history."
        );
        return;
      }

      await loadHistory();

      setMessage(
        "Scan history deleted successfully."
      );
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to delete scan history."
      );
    }
  };

  // ============================================================
  // CLEAR ALL HISTORY
  // ============================================================

  const clearAllHistory = async () => {
    const confirmDelete = window.confirm(
      "Delete all scan history?"
    );

    if (!confirmDelete) return;

    try {
      const currentToken = getToken();

      const response = await fetch(
        `${API_URL}/history`,
        {
          method: "DELETE",

          headers: {
            Authorization:
              `Bearer ${currentToken}`
          }
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.error ||
          "Failed to delete history."
        );
        return;
      }

      setHistory([]);

      setMessage(
        "All scan history deleted."
      );
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to delete history."
      );
    }
  };

  // ============================================================
  // DOWNLOAD FILE HELPER
  // ============================================================

  const downloadFile = (
    content,
    filename,
    type
  ) => {
    const blob = new Blob(
      [content],
      { type }
    );

    const url =
      URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

    URL.revokeObjectURL(url);
  };

  // ============================================================
  // HTML REPORT
  // ============================================================

  const generateHTMLReport = () => {
    if (!results.length) {
      setMessage("Please perform a scan first.");
      return;
    }

    const rows = results
      .map(
        (item) => `
        <tr>
          <td>${item.port ?? "-"}</td>
          <td>${item.state ?? "-"}</td>
          <td>${item.service ?? "-"}</td>
          <td>${item.version ?? "-"}</td>
          <td>${item.risk ?? "-"}</td>
          <td>${item.recommendation ?? "-"}</td>
        </tr>
      `
      )
      .join("");

    const html = `
<!DOCTYPE html>

<html>

<head>

<title>Port Scanner Security Report</title>

<style>

body {
  font-family: Arial, sans-serif;
  background: #f4f7fb;
  color: #172033;
  padding: 40px;
}

.container {
  max-width: 1200px;
  margin: auto;
}

h1 {
  color: #0f4c81;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: white;
}

th {
  background: #0f4c81;
  color: white;
}

th, td {
  padding: 12px;
  border: 1px solid #ddd;
  text-align: left;
}

</style>

</head>

<body>

<div class="container">

<h1>Port Scanner Security Report</h1>

<p><strong>Target:</strong> ${target}</p>

<p>
<strong>Scan Duration:</strong>
${scanDuration || "-"} seconds
</p>

<table>

<thead>

<tr>
<th>Port</th>
<th>State</th>
<th>Service</th>
<th>Version</th>
<th>Risk</th>
<th>Recommendation</th>
</tr>

</thead>

<tbody>

${rows}

</tbody>

</table>

</div>

</body>

</html>
`;

    downloadFile(
      html,
      `port-scan-${target}.html`,
      "text/html"
    );

    setMessage(
      "HTML report generated successfully."
    );
  };

  // ============================================================
  // PDF REPORT
  // ============================================================

  const downloadPDF = () => {
    if (!results.length) {
      setMessage("Please perform a scan first.");
      return;
    }

    const doc = new jsPDF();

    doc.setFontSize(20);

    doc.text(
      "Port Scanner Security Report",
      14,
      20
    );

    doc.setFontSize(11);

    doc.text(
      `Target: ${target}`,
      14,
      32
    );

    doc.text(
      `Scan Duration: ${
        scanDuration || "-"
      } seconds`,
      14,
      40
    );

    const tableData = results.map(
      (item) => [
        item.port ?? "-",
        item.state ?? "-",
        item.service ?? "-",
        item.version ?? "-",
        item.risk ?? "-",
        item.recommendation ?? "-"
      ]
    );

    autoTable(doc, {
      startY: 50,

      head: [[
        "Port",
        "State",
        "Service",
        "Version",
        "Risk",
        "Recommendation"
      ]],

      body: tableData,

      styles: {
        fontSize: 8
      }
    });

    doc.save(
      `port-scan-${target}.pdf`
    );

    setMessage(
      "PDF report downloaded successfully."
    );
  };

  // ============================================================
  // XML REPORT
  // ============================================================

  const downloadXML = () => {
    if (!results.length) {
      setMessage("Please perform a scan first.");
      return;
    }

    let xml = `<?xml version="1.0" encoding="UTF-8"?>

<portScannerReport>

  <target>${target}</target>

  <scanDuration>
    ${scanDuration}
  </scanDuration>

  <results>`;

    results.forEach((item) => {
      xml += `

    <port>

      <number>
        ${item.port ?? "-"}
      </number>

      <state>
        ${item.state ?? "-"}
      </state>

      <service>
        ${item.service ?? "-"}
      </service>

      <version>
        ${item.version ?? "-"}
      </version>

      <risk>
        ${item.risk ?? "-"}
      </risk>

    </port>`;
    });

    xml += `

  </results>

</portScannerReport>`;

    downloadFile(
      xml,
      `port-scan-${target}.xml`,
      "application/xml"
    );

    setMessage(
      "XML report downloaded successfully."
    );
  };

  // ============================================================
  // EMAIL REPORT
  // ============================================================

  const sendEmailReport = async () => {
    if (!results.length) {
      setMessage(
        "Please perform a scan first."
      );

      return;
    }

    if (!recipientEmail.trim()) {
      setMessage(
        "Please enter a recipient email."
      );

      return;
    }

    setMessage("Sending email report...");

    try {
      const response = await fetch(
        `${API_URL}/email-report`,
        {
          method: "POST",

          headers: authHeaders(),

          body: JSON.stringify({
            recipient:
              recipientEmail.trim(),

            target,

            results,

            scan_duration:
              scanDuration
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setMessage(
          data.error ||
          "Failed to send email report."
        );

        return;
      }

      setMessage(
        `Report sent to ${recipientEmail}`
      );

      setRecipientEmail("");
    } catch (error) {
      console.error(error);

      setMessage(
        "Unable to send email report."
      );
    }
  };

  // ============================================================
  // LOGIN PAGE
  // ============================================================

  if (!token) {
    return (
      <div className="auth-page">

        <div className="space-background">
          <div className="star star-1"></div>
          <div className="star star-2"></div>
          <div className="star star-3"></div>
          <div className="star star-4"></div>

          <div className="auth-orbit"></div>
        </div>

        <div className="auth-wrapper">

          <div className="auth-left">

            <div className="brand-badge">
              SECURITY PLATFORM
            </div>

            <h1>
              Network
              <span> Intelligence</span>
            </h1>

            <p>
              Professional network reconnaissance
              and port analysis platform.
            </p>

            <div className="auth-features">

              <div>
                <span>◈</span>
                Advanced Port Scanning
              </div>

              <div>
                <span>◈</span>
                Service Detection
              </div>

              <div>
                <span>◈</span>
                Security Intelligence
              </div>

            </div>

          </div>

          <div className="auth-card">

            <div className="auth-card-header">

              <div className="auth-shield">
                ◈
              </div>

              <div>
                <h2>
                  {
                    authMode === "login"
                      ? "Welcome back"
                      : "Create account"
                  }
                </h2>

                <p>
                  {
                    authMode === "login"
                      ? "Sign in to your security workspace"
                      : "Create your security workspace"
                  }
                </p>
              </div>

            </div>

            <form onSubmit={handleAuth}>

              <div className="input-group">

                <label>
                  Username
                </label>

                <input
                  type="text"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value)
                  }
                  required
                />

              </div>

              <div className="input-group">

                <label>
                  Password
                </label>

                <div className="password-wrapper">

                  <input
                    type={
                      showPassword
                        ? "text"
                        : "password"
                    }
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) =>
                      setPassword(e.target.value)
                    }
                    required
                  />

                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() =>
                      setShowPassword(
                        !showPassword
                      )
                    }
                  >
                    {
                      showPassword
                        ? "Hide"
                        : "Show"
                    }
                  </button>

                </div>

              </div>

              <button
                className="auth-submit"
                type="submit"
              >
                {
                  authMode === "login"
                    ? "Access Dashboard"
                    : "Create Account"
                }

                <span>→</span>
              </button>

            </form>

            <div className="auth-divider">
              <span></span>
              OR
              <span></span>
            </div>

            <button
              className="auth-switch"
              onClick={() => {
                setAuthMode(
                  authMode === "login"
                    ? "register"
                    : "login"
                );

                setMessage("");
              }}
            >
              {
                authMode === "login"
                  ? "Create a new account"
                  : "Already have an account?"
              }
            </button>

            {
              message && (
                <div className="auth-message">
                  {message}
                </div>
              )
            }

          </div>

        </div>

      </div>
    );
  }

  // ============================================================
  // MAIN APPLICATION
  // ============================================================

  return (
    <div className="app-shell">

      {/* BACKGROUND */}

      <div className="app-background">
        <div className="grid-overlay"></div>

        <div className="orb orb-one"></div>
        <div className="orb orb-two"></div>

        <div className="background-stars"></div>
      </div>

      {/* ======================================================
          SIDEBAR
      ====================================================== */}

      <aside className="sidebar">

        <div className="sidebar-brand">

          <div className="brand-icon">
            ◈
          </div>

          <div className="brand-text">
            <h2>PORTSEC</h2>
            <p>NETWORK INTELLIGENCE</p>
          </div>

        </div>

        <div className="sidebar-label">
          WORKSPACE
        </div>

        <nav className="sidebar-nav">

          <button
            className={
              activePage === "dashboard"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setActivePage("dashboard")
            }
          >
            <span className="nav-icon">
              ◫
            </span>

            <span>
              Dashboard
            </span>

          </button>

          <button
            className={
              activePage === "scan"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setActivePage("scan")
            }
          >
            <span className="nav-icon">
              ◎
            </span>

            <span>
              New Scan
            </span>

          </button>

          <button
            className={
              activePage === "results"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setActivePage("results")
            }
          >
            <span className="nav-icon">
              ◉
            </span>

            <span>
              Results
            </span>

            {
              results.length > 0 && (
                <span className="nav-count">
                  {results.length}
                </span>
              )
            }

          </button>

          <button
            className={
              activePage === "history"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() =>
              setActivePage("history")
            }
          >
            <span className="nav-icon">
              ◷
            </span>

            <span>
              History
            </span>

            {
              history.length > 0 && (
                <span className="nav-count">
                  {history.length}
                </span>
              )
            }

          </button>

        </nav>

        <div className="sidebar-system">

          <div className="system-title">
            SYSTEM STATUS
          </div>

          <div className="system-row">

            <span className="system-dot"></span>

            <div>
              <strong>
                Operational
              </strong>

              <p>
                Scanner Engine Ready
              </p>
            </div>

          </div>

        </div>

        <div className="sidebar-user">

          <div className="user-profile">

            <div className="user-avatar">
              {
                loggedInUser
                  ?.charAt(0)
                  ?.toUpperCase() || "U"
              }
            </div>

            <div className="user-details">
              <strong>
                {loggedInUser}
              </strong>

              <span>
                Security Analyst
              </span>
            </div>

          </div>

          <button
            className="logout-button"
            onClick={handleLogout}
          >
            <span>↪</span>
            Logout
          </button>

        </div>

      </aside>

      {/* ======================================================
          MAIN
      ====================================================== */}

      <main className="main-content">

        {/* TOPBAR */}

        <header className="topbar">

          <div>

            <div className="breadcrumb">
              PORTSEC
              <span>/</span>

              {
                activePage.toUpperCase()
              }
            </div>

            <h1>

              {
                activePage === "dashboard"
                  ? "Security Overview"
                  : activePage === "scan"
                  ? "Network Scanner"
                  : activePage === "results"
                  ? "Scan Intelligence"
                  : "Scan Archive"
              }

            </h1>

          </div>

          <div className="topbar-right">

            <div className="online-status">
              <span></span>
              SYSTEM ONLINE
            </div>

            <div className="topbar-user">
              {loggedInUser}
            </div>

          </div>

        </header>

        {/* MESSAGE */}

        {
          message && (
            <div className="global-message">
              <span>●</span>
              {message}

              <button
                onClick={() =>
                  setMessage("")
                }
              >
                ×
              </button>
            </div>
          )
        }

        {/* ====================================================
            DASHBOARD
        ==================================================== */}

        {
          activePage === "dashboard" && (

            <div className="page-content page-enter">

              {/* HERO */}

              <section className="dashboard-hero">

                <div className="hero-content">

                  <div className="hero-label">
                    <span></span>
                    SECURITY COMMAND CENTER
                  </div>

                  <h2>
                    Monitor your
                    <br />

                    <span>
                      network surface.
                    </span>
                  </h2>

                  <p>
                    Perform reconnaissance,
                    identify exposed services
                    and analyze potential
                    security risks.
                  </p>

                  <button
                    className="hero-button"
                    onClick={() =>
                      setActivePage("scan")
                    }
                  >
                    <span>◎</span>
                    Start New Scan
                  </button>

                </div>

                <div className="radar-container">

                  <div className="radar">

                    <div className="radar-ring ring-1"></div>
                    <div className="radar-ring ring-2"></div>
                    <div className="radar-ring ring-3"></div>

                    <div className="radar-line"></div>

                    <div className="radar-center"></div>

                    <div className="radar-point point-1"></div>
                    <div className="radar-point point-2"></div>
                    <div className="radar-point point-3"></div>

                  </div>

                </div>

              </section>

              {/* STATS */}

              <section className="stats-grid">

                <div className="stat-card">

                  <div className="stat-card-top">

                    <span>
                      TOTAL SCANS
                    </span>

                    <div className="stat-symbol">
                      ◫
                    </div>

                  </div>

                  <h2>
                    {history.length}
                  </h2>

                  <p>
                    <span className="positive">
                      ↑
                    </span>

                    Scan records available
                  </p>

                </div>

                <div className="stat-card">

                  <div className="stat-card-top">

                    <span>
                      OPEN PORTS
                    </span>

                    <div className="stat-symbol blue">
                      ◎
                    </div>

                  </div>

                  <h2>
                    {openPortsCount}
                  </h2>

                  <p>
                    Current scan exposure
                  </p>

                </div>

                <div className="stat-card risk-card">

                  <div className="stat-card-top">

                    <span>
                      HIGH RISK
                    </span>

                    <div className="stat-symbol danger">
                      !
                    </div>

                  </div>

                  <h2>
                    {highRiskCount}
                  </h2>

                  <p>
                    Requires attention
                  </p>

                </div>

                <div className="stat-card">

                  <div className="stat-card-top">

                    <span>
                      LAST TARGET
                    </span>

                    <div className="stat-symbol">
                      ◉
                    </div>

                  </div>

                  <h2 className="target-value">
                    {target || "—"}
                  </h2>

                  <p>
                    Latest scan target
                  </p>

                </div>

              </section>

              {/* BOTTOM GRID */}

              <section className="dashboard-grid">

                <div className="panel activity-panel">

                  <div className="panel-header">

                    <div>

                      <span className="panel-label">
                        ACTIVITY
                      </span>

                      <h3>
                        Recent Scans
                      </h3>

                    </div>

                    <button
                      className="text-button"
                      onClick={() =>
                        setActivePage("history")
                      }
                    >
                      View All →
                    </button>

                  </div>

                  {
                    history.length === 0

                      ? (

                        <div className="empty-panel">

                          <div>
                            ◌
                          </div>

                          <h4>
                            No activity yet
                          </h4>

                          <p>
                            Start your first
                            network scan.
                          </p>

                        </div>

                      )

                      : (

                        <div className="activity-list">

                          {
                            history
                              .slice(0, 5)
                              .map(
                                (
                                  item,
                                  index
                                ) => (

                                  <div
                                    className="activity-item"
                                    key={
                                      item.id ??
                                      index
                                    }
                                  >

                                    <div className="activity-icon">
                                      ◉
                                    </div>

                                    <div className="activity-info">

                                      <strong>
                                        {item.target}
                                      </strong>

                                      <span>

                                        {
                                          item.created_at

                                            ? new Date(
                                                item.created_at
                                              ).toLocaleString()

                                            : "Unknown date"
                                        }

                                      </span>

                                    </div>

                                    <button
                                      className="small-view"
                                      onClick={() =>
                                        loadHistoryItem(
                                          item
                                        )
                                      }
                                    >
                                      View
                                    </button>

                                  </div>

                                )
                              )
                          }

                        </div>

                      )
                  }

                </div>

                <div className="panel threat-panel">

                  <div className="panel-header">

                    <div>

                      <span className="panel-label">
                        RISK ANALYSIS
                      </span>

                      <h3>
                        Threat Distribution
                      </h3>

                    </div>

                  </div>

                  <div className="risk-chart">

                    <div className="chart-center">

                      <strong>
                        {results.length}
                      </strong>

                      <span>
                        RESULTS
                      </span>

                    </div>

                  </div>

                  <div className="risk-legend">

                    <div>
                      <span className="legend-dot high"></span>

                      High

                      <strong>
                        {highRiskCount}
                      </strong>
                    </div>

                    <div>
                      <span className="legend-dot medium"></span>

                      Medium

                      <strong>
                        {mediumRiskCount}
                      </strong>
                    </div>

                    <div>
                      <span className="legend-dot low"></span>

                      Low

                      <strong>
                        {lowRiskCount}
                      </strong>
                    </div>

                  </div>

                </div>

              </section>

            </div>

          )
        }

        {/* ====================================================
            SCAN PAGE
        ==================================================== */}

        {
          activePage === "scan" && (

            <div className="page-content page-enter">

              <section className="scanner-panel">

                <div className="scanner-header">

                  <div>

                    <span className="panel-label">
                      RECONNAISSANCE MODULE
                    </span>

                    <h2>
                      Initiate Network Scan
                    </h2>

                    <p>
                      Configure your scan parameters
                      and analyze the target.
                    </p>

                  </div>

                  <div className="scanner-status">
                    <span></span>
                    ENGINE READY
                  </div>

                </div>

                <div className="target-section">

                  <label>
                    TARGET ADDRESS
                  </label>

                  <div className="target-input-wrapper">

                    <span className="target-prefix">
                      ›_
                    </span>

                    <input
                      type="text"
                      placeholder="example.com or 192.168.1.1"
                      value={target}
                      onChange={(e) =>
                        setTarget(e.target.value)
                      }
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          scanTarget();
                        }
                      }}
                    />

                    <div className="target-status">
                      READY
                    </div>

                  </div>

                </div>

                {/* SCAN OPTIONS */}

                <div className="scan-config-header">

                  <div>

                    <label>
                      SCAN CONFIGURATION
                    </label>

                    <p>
                      Select one or more scanning
                      techniques.
                    </p>

                  </div>

                  <button
                    className="select-options-button"
                    onClick={() =>
                      setShowScanOptions(
                        !showScanOptions
                      )
                    }
                  >
                    {selectedOptions.length}
                    {" "}
                    SELECTED

                    <span>
                      {
                        showScanOptions
                          ? "▲"
                          : "▼"
                      }
                    </span>

                  </button>

                </div>

                {
                  showScanOptions && (

                    <div className="scan-options-grid">

                      {
                        scanOptions.map(
                          (option) => (

                            <div
                              key={option.id}
                              className={
                                selectedOptions.includes(
                                  option.id
                                )

                                  ? "scan-option-card selected"

                                  : "scan-option-card"
                              }
                              onClick={() =>
                                toggleScanOption(
                                  option.id
                                )
                              }
                            >

                              <div className="option-icon">
                                {option.icon}
                              </div>

                              <div className="option-content">

                                <strong>
                                  {option.label}
                                </strong>

                                <span>
                                  {option.description}
                                </span>

                              </div>

                              <div
                                className="option-checkbox"
                              >
                                {
                                  selectedOptions.includes(
                                    option.id
                                  )

                                    ? "✓"

                                    : ""
                                }
                              </div>

                            </div>

                          )
                        )
                      }

                    </div>

                  )
                }

                {/* SELECTED */}

                <div className="selected-techniques">

                  <span>
                    ACTIVE TECHNIQUES
                  </span>

                  <div>

                    {
                      scanOptions
                        .filter((option) =>
                          selectedOptions.includes(
                            option.id
                          )
                        )
                        .map((option) => (

                          <span
                            className="tech-tag"
                            key={option.id}
                          >
                            {option.label}
                          </span>

                        ))
                    }

                  </div>

                </div>

                {/* SCAN BUTTON */}

                <button
                  className={
                    loading

                      ? "launch-scan-button scanning"

                      : "launch-scan-button"
                  }
                  onClick={scanTarget}
                  disabled={loading}
                >

                  {
                    loading

                      ? (

                        <>
                          <span className="scan-loader"></span>

                          SCANNING TARGET...
                        </>

                      )

                      : (

                        <>
                          <span>
                            ◎
                          </span>

                          LAUNCH SCAN

                          <span className="arrow">
                            →
                          </span>

                        </>

                      )
                  }

                </button>

              </section>

              {/* SCANNING ANIMATION */}

              {
                loading && (

                  <section className="live-scan-panel">

                    <div className="live-scan-left">

                      <div className="live-label">
                        LIVE SCAN
                      </div>

                      <h3>
                        Analyzing target
                        <span>.</span>
                        <span>.</span>
                        <span>.</span>
                      </h3>

                      <p>
                        Target:
                        {" "}
                        <strong>
                          {target}
                        </strong>
                      </p>

                    </div>

                    <div className="scan-visual">

                      <div className="scan-rings">

                        <div></div>
                        <div></div>
                        <div></div>

                      </div>

                      <div className="scan-core">
                        ◉
                      </div>

                    </div>

                  </section>

                )
              }

            </div>

          )
        }

        {/* ====================================================
            RESULTS PAGE
        ==================================================== */}

        {
          activePage === "results" && (

            <div className="page-content page-enter">

              <section className="results-header">

                <div>

                  <span className="panel-label">
                    SECURITY INTELLIGENCE
                  </span>

                  <h2>
                    Scan Results
                  </h2>

                  <p>
                    {
                      target
                        ? `Analysis for ${target}`
                        : "No active scan loaded"
                    }
                  </p>

                </div>

                {
                  results.length > 0 && (

                    <button
                      className="new-scan-top-button"
                      onClick={() =>
                        setActivePage("scan")
                      }
                    >
                      + New Scan
                    </button>

                  )
                }

              </section>

              {
                results.length === 0

                  ? (

                    <section className="empty-state">

                      <div className="empty-symbol">
                        ◌
                      </div>

                      <h3>
                        No Scan Results
                      </h3>

                      <p>
                        Launch a network scan
                        to generate intelligence.
                      </p>

                      <button
                        onClick={() =>
                          setActivePage("scan")
                        }
                      >
                        Start New Scan →
                      </button>

                    </section>

                  )

                  : (

                    <>

                      {/* RESULT SUMMARY */}

                      <section className="result-summary-grid">

                        <div className="result-summary-card">

                          <span>
                            DISCOVERED
                          </span>

                          <strong>
                            {results.length}
                          </strong>

                          <p>
                            Services Found
                          </p>

                        </div>

                        <div className="result-summary-card danger-summary">

                          <span>
                            HIGH RISK
                          </span>

                          <strong>
                            {highRiskCount}
                          </strong>

                          <p>
                            Requires Review
                          </p>

                        </div>

                        <div className="result-summary-card">

                          <span>
                            SCAN TIME
                          </span>

                          <strong>
                            {scanDuration || "—"}
                          </strong>

                          <p>
                            Seconds
                          </p>

                        </div>

                        <div className="result-summary-card">

                          <span>
                            TARGET
                          </span>

                          <strong className="summary-target">
                            {target}
                          </strong>

                          <p>
                            Network Asset
                          </p>

                        </div>

                      </section>

                      {/* TABLE */}

                      <section className="results-table-panel">

                        <div className="table-header">

                          <div>

                            <h3>
                              Discovered Services
                            </h3>

                            <p>
                              Detailed port and
                              vulnerability information
                            </p>

                          </div>

                          <div className="result-count">
                            {results.length}
                            {" "}
                            RESULTS
                          </div>

                        </div>

                        <div className="table-container">

                          <table>

                            <thead>

                              <tr>

                                <th>
                                  PORT
                                </th>

                                <th>
                                  STATE
                                </th>

                                <th>
                                  SERVICE
                                </th>

                                <th>
                                  VERSION
                                </th>

                                <th>
                                  RISK
                                </th>

                                <th>
                                  RECOMMENDATION
                                </th>

                                <th>
                                  CVE
                                </th>

                              </tr>

                            </thead>

                            <tbody>

                              {
                                results.map(
                                  (
                                    item,
                                    index
                                  ) => (

                                    <tr
                                      key={index}
                                    >

                                      <td>

                                        <span className="port-number">

                                          {item.port ?? "-"}

                                        </span>

                                      </td>

                                      <td>

                                        <span
                                          className={
                                            String(
                                              item.state ||
                                              ""
                                            )
                                              .toLowerCase()
                                              .includes("open")

                                              ? "state-open"

                                              : "state-other"
                                          }
                                        >

                                          <span></span>

                                          {item.state ?? "-"}

                                        </span>

                                      </td>

                                      <td>

                                        <strong className="service-name">

                                          {item.service ?? "-"}

                                        </strong>

                                      </td>

                                      <td className="version-cell">

                                        {item.version ?? "-"}

                                      </td>

                                      <td>

                                        <span
                                          className={`risk-badge ${getRiskClass(
                                            item.risk
                                          )}`}
                                        >

                                          {item.risk ?? "Unknown"}

                                        </span>

                                      </td>

                                      <td className="recommendation-cell">

                                        {item.recommendation ?? "-"}

                                      </td>

                                      <td>

                                        {
                                          item.cves &&
                                          item.cves.length > 0

                                            ? (

                                              <div className="cve-list">

                                                {
                                                  item.cves.map(
                                                    (
                                                      cve,
                                                      cveIndex
                                                    ) => (

                                                      <div
                                                        className="cve-item"
                                                        key={cveIndex}
                                                      >

                                                        <strong>

                                                          {
                                                            cve.cve_id
                                                          }

                                                        </strong>

                                                        {
                                                          cve.cvss_score !==
                                                            null &&

                                                          cve.cvss_score !==
                                                            undefined && (

                                                            <span>

                                                              CVSS
                                                              {" "}
                                                              {
                                                                cve.cvss_score
                                                              }

                                                            </span>

                                                          )
                                                        }

                                                      </div>

                                                    )
                                                  )
                                                }

                                              </div>

                                            )

                                            : (

                                              <span className="no-cve">

                                                None

                                              </span>

                                            )
                                        }

                                      </td>

                                    </tr>

                                  )
                                )
                              }

                            </tbody>

                          </table>

                        </div>

                      </section>

                      {/* REPORT CENTER */}

                      <section className="report-center">

                        <div className="report-header">

                          <div>

                            <span className="panel-label">
                              EXPORT CENTER
                            </span>

                            <h3>
                              Generate Report
                            </h3>

                            <p>
                              Export security intelligence
                              in multiple formats.
                            </p>

                          </div>

                        </div>

                        <div className="report-grid">

                          <button
                            onClick={generateHTMLReport}
                            className="report-card"
                          >

                            <div>
                              ◫
                            </div>

                            <strong>
                              HTML Report
                            </strong>

                            <span>
                              Interactive report
                            </span>

                          </button>

                          <button
                            onClick={downloadPDF}
                            className="report-card"
                          >

                            <div>
                              ▤
                            </div>

                            <strong>
                              PDF Report
                            </strong>

                            <span>
                              Professional document
                            </span>

                          </button>

                          <button
                            onClick={downloadXML}
                            className="report-card"
                          >

                            <div>
                              &lt;/&gt;
                            </div>

                            <strong>
                              XML Report
                            </strong>

                            <span>
                              Machine readable data
                            </span>

                          </button>

                        </div>

                      </section>

                      {/* EMAIL */}

                      <section className="email-panel">

                        <div className="email-icon">
                          ✉
                        </div>

                        <div className="email-content">

                          <h3>
                            Send Security Report
                          </h3>

                          <p>
                            Send scan intelligence
                            directly to a recipient.
                          </p>

                        </div>

                        <div className="email-form">

                          <input
                            type="email"
                            placeholder="security@example.com"
                            value={recipientEmail}
                            onChange={(e) =>
                              setRecipientEmail(
                                e.target.value
                              )
                            }
                          />

                          <button
                            onClick={sendEmailReport}
                          >
                            Send →
                          </button>

                        </div>

                      </section>

                    </>

                  )
              }

            </div>

          )
        }

        {/* ====================================================
            HISTORY PAGE
        ==================================================== */}

        {
          activePage === "history" && (

            <div className="page-content page-enter">

              <section className="results-header">

                <div>

                  <span className="panel-label">
                    SCAN ARCHIVE
                  </span>

                  <h2>
                    Scan History
                  </h2>

                  <p>
                    Review and manage previous
                    network reconnaissance.
                  </p>

                </div>

                {
                  history.length > 0 && (

                    <button
                      className="delete-all-button"
                      onClick={clearAllHistory}
                    >
                      Delete All
                    </button>

                  )
                }

              </section>

              {
                history.length === 0

                  ? (

                    <section className="empty-state">

                      <div className="empty-symbol">
                        ◷
                      </div>

                      <h3>
                        No Scan History
                      </h3>

                      <p>
                        Completed scans will
                        appear here.
                      </p>

                      <button
                        onClick={() =>
                          setActivePage("scan")
                        }
                      >
                        Start Your First Scan →
                      </button>

                    </section>

                  )

                  : (

                    <section className="history-timeline">

                      {
                        history.map(
                          (
                            item,
                            index
                          ) => (

                            <div
                              className="history-card"
                              key={
                                item.id ??
                                index
                              }
                            >

                              <div className="history-index">

                                {String(
                                  index + 1
                                ).padStart(2, "0")}

                              </div>

                              <div className="history-main">

                                <div className="history-title-row">

                                  <div>

                                    <span className="history-label">

                                      TARGET

                                    </span>

                                    <h3>

                                      {item.target}

                                    </h3>

                                  </div>

                                  <div className="history-status">

                                    COMPLETED

                                  </div>

                                </div>

                                <div className="history-meta">

                                  <span>

                                    ◷

                                    {
                                      item.created_at

                                        ? new Date(
                                            item.created_at
                                          ).toLocaleString()

                                        : "Unknown"
                                    }

                                  </span>

                                  <span>

                                    ◌

                                    Duration:

                                    {" "}

                                    {
                                      item.scan_duration ??
                                      "-"
                                    }

                                    s

                                  </span>

                                </div>

                              </div>

                              <div className="history-buttons">

                                <button
                                  className="history-view"
                                  onClick={() =>
                                    loadHistoryItem(
                                      item
                                    )
                                  }
                                >
                                  View
                                </button>

                                <button
                                  className="history-delete"
                                  onClick={() =>
                                    deleteHistoryItem(
                                      item
                                    )
                                  }
                                >
                                  Delete
                                </button>

                              </div>

                            </div>

                          )
                        )
                      }

                    </section>

                  )
              }

            </div>

          )
        }

      </main>

    </div>
  );
}

export default App;
