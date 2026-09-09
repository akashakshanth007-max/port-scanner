import { useEffect, useState } from "react";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import "./App.css";

const API_URL = "https://port-scanner-1-at12.onrender.com";

function App() {
  // ============================================================
  // AUTH
  // ============================================================

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState("login");

  const [token, setToken] = useState(
    localStorage.getItem("access_token") || ""
  );

  const [loggedInUser, setLoggedInUser] = useState(
    localStorage.getItem("username") || ""
  );

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
  // EMAIL
  // ============================================================

  const [recipientEmail, setRecipientEmail] = useState("");

  // ============================================================
  // TOKEN
  // ============================================================

  const getToken = () => {
    return localStorage.getItem("access_token") || token;
  };

  // ============================================================
  // AUTH HEADERS
  // ============================================================

  const authHeaders = () => {
    const currentToken = getToken();

    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${currentToken}`,
    };
  };

  // ============================================================
  // LOAD SUPABASE HISTORY
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
            Authorization: `Bearer ${currentToken}`,
          },
        }
      );

      // --------------------------------------------------------
      // TOKEN EXPIRED / INVALID
      // --------------------------------------------------------

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
          data.error ||
            "Failed to load scan history."
        );

        return;
      }

      setHistory(
        data.history || []
      );

    } catch (error) {
      console.error(
        "History error:",
        error
      );

      setMessage(
        "Unable to load scan history."
      );
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
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            username,
            password,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        setMessage(
          data.error ||
            "Authentication failed."
        );

        return;
      }

      // --------------------------------------------------------
      // REGISTER
      // --------------------------------------------------------

      if (
        authMode === "register"
      ) {
        setMessage(
          "Registration successful. Please login."
        );

        setAuthMode("login");

        setPassword("");

        return;
      }

      // --------------------------------------------------------
      // LOGIN
      // --------------------------------------------------------

      localStorage.setItem(
        "access_token",
        data.access_token
      );

      localStorage.setItem(
        "username",
        data.username
      );

      setToken(
        data.access_token
      );

      setLoggedInUser(
        data.username
      );

      setUsername("");
      setPassword("");

      setMessage(
        "Login successful."
      );

    } catch (error) {
      console.error(
        "Authentication error:",
        error
      );

      setMessage(
        "Unable to connect to backend."
      );
    }
  };

  // ============================================================
  // LOGOUT
  // ============================================================

  const handleLogout = () => {
    localStorage.removeItem(
      "access_token"
    );

    localStorage.removeItem(
      "username"
    );

    setToken("");

    setLoggedInUser("");

    setResults([]);

    setTarget("");

    setHistory([]);

    setScanDuration("");

    setRecipientEmail("");

    setMessage(
      "Logged out successfully."
    );
  };

  // ============================================================
  // SCAN
  // ============================================================

  const scanTarget = async () => {
    if (!target.trim()) {
      setMessage(
        "Please enter an IP address or domain."
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

    try {
      const response = await fetch(
        `${API_URL}/scan`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${currentToken}`,
          },

          body: JSON.stringify({
            target:
              target.trim(),
          }),
        }
      );

      // --------------------------------------------------------
      // TOKEN ERROR
      // --------------------------------------------------------

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

      const data =
        await response.json();

      // --------------------------------------------------------
      // OTHER ERROR
      // --------------------------------------------------------

      if (!response.ok) {
        console.error(
          "Scan error:",
          data
        );

        setMessage(
          data.details ||
            data.error ||
            "Scan failed."
        );

        return;
      }

      // --------------------------------------------------------
      // RESULTS
      // --------------------------------------------------------

      const scanResults =
        data.results || [];

      setResults(
        scanResults
      );

      // --------------------------------------------------------
      // USE BACKEND SCAN DURATION
      // --------------------------------------------------------

      const duration =
        data.scan_duration ??
        "-";

      setScanDuration(
        duration
      );

      // --------------------------------------------------------
      // REFRESH SUPABASE HISTORY
      // --------------------------------------------------------

      await loadHistory();

      // --------------------------------------------------------
      // SUCCESS MESSAGE
      // --------------------------------------------------------

      setMessage(
        `Scan completed successfully. ${scanResults.length} result(s) found.`
      );

    } catch (error) {
      console.error(
        "Scan error:",
        error
      );

      setMessage(
        "Unable to connect to backend. Make sure Flask server is running."
      );

    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // LOAD HISTORY ITEM
  // ============================================================

  const loadHistoryItem = (item) => {
    setTarget(
      item.target || ""
    );

    let savedResults =
      item.results || [];

    // ----------------------------------------------------------
    // SUPABASE JSON SAFETY
    // ----------------------------------------------------------

    if (
      typeof savedResults === "string"
    ) {
      try {
        savedResults =
          JSON.parse(
            savedResults
          );
      } catch {
        savedResults = [];
      }
    }

    setResults(
      savedResults
    );

    setScanDuration(
      item.scan_duration ??
        ""
    );

    setMessage(
      "Previous scan loaded."
    );
  };

  // ============================================================
  // DELETE ONE HISTORY
  // ============================================================

  const deleteHistoryItem = async (item) => {
    const confirmDelete =
      window.confirm(
        "Delete this scan history?"
      );

    if (!confirmDelete) {
      return;
    }

    try {
      const currentToken = getToken();

      if (!currentToken) {
        setMessage(
          "Please login again."
        );

        return;
      }

      // --------------------------------------------------------
      // DELETE FROM SUPABASE THROUGH BACKEND
      // --------------------------------------------------------

      const response = await fetch(
        `${API_URL}/history/${item.id}`,
        {
          method: "DELETE",

          headers: {
            Authorization:
              `Bearer ${currentToken}`,
          },
        }
      );

      // --------------------------------------------------------
      // TOKEN ERROR
      // --------------------------------------------------------

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

      const data =
        await response.json();

      // --------------------------------------------------------
      // DELETE ERROR
      // --------------------------------------------------------

      if (!response.ok) {
        console.error(
          "Delete history error:",
          data
        );

        setMessage(
          data.details ||
            data.error ||
            "Failed to delete scan history."
        );

        return;
      }

      // --------------------------------------------------------
      // REFRESH HISTORY FROM SUPABASE
      // --------------------------------------------------------

      await loadHistory();

      setMessage(
        "Scan history deleted successfully."
      );

    } catch (error) {
      console.error(
        "Delete history error:",
        error
      );

      setMessage(
        "Unable to delete scan history."
      );
    }
  };

  // ============================================================
  // DELETE ALL HISTORY
  // ============================================================

  const clearAllHistory = async () => {
    const confirmDelete =
      window.confirm(
        "Delete all scan history?"
      );

    if (!confirmDelete) {
      return;
    }

    try {
      const currentToken = getToken();

      if (!currentToken) {
        setMessage(
          "Please login again."
        );

        return;
      }

      // --------------------------------------------------------
      // DELETE ALL FROM SUPABASE THROUGH BACKEND
      // --------------------------------------------------------

      const response = await fetch(
        `${API_URL}/history`,
        {
          method: "DELETE",

          headers: {
            Authorization:
              `Bearer ${currentToken}`,
          },
        }
      );

      // --------------------------------------------------------
      // TOKEN ERROR
      // --------------------------------------------------------

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

      const data =
        await response.json();

      // --------------------------------------------------------
      // DELETE ERROR
      // --------------------------------------------------------

      if (!response.ok) {
        console.error(
          "Delete all history error:",
          data
        );

        setMessage(
          data.details ||
            data.error ||
            "Failed to delete all scan history."
        );

        return;
      }

      // --------------------------------------------------------
      // CLEAR CURRENT VIEW
      // --------------------------------------------------------

      setHistory([]);

      setMessage(
        "All scan history deleted successfully."
      );

    } catch (error) {
      console.error(
        "Delete all history error:",
        error
      );

      setMessage(
        "Unable to delete all scan history."
      );
    }
  };

  // ============================================================
  // HTML REPORT
  // ============================================================

  const generateHTMLReport = () => {
    if (!results.length) {
      setMessage(
        "Please perform a scan first."
      );

      return;
    }

    const rows = results
      .map(
        (item) => `
          <tr>

            <td>
              ${item.port ?? "-"}
            </td>

            <td>
              ${item.state ?? "-"}
            </td>

            <td>
              ${item.service ?? "-"}
            </td>

            <td>
              ${item.version ?? "-"}
            </td>

            <td>
              ${item.risk ?? "-"}
            </td>

            <td>
              ${item.recommendation ?? "-"}
            </td>

          </tr>
        `
      )
      .join("");

    const html = `
      <!DOCTYPE html>

      <html>

      <head>

        <title>
          Port Scanner Report
        </title>

        <style>

          body {
            font-family: Arial, sans-serif;
            margin: 40px;
          }

          h1 {
            color: #222;
          }

          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
          }

          th,
          td {
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
          }

          th {
            background: #f2f2f2;
          }

        </style>

      </head>

      <body>

        <h1>
          Port Scanner Report
        </h1>

        <p>

          <strong>
            Target:
          </strong>

          ${target}

        </p>

        <p>

          <strong>
            Scan Duration:
          </strong>

          ${scanDuration || "-"}
          seconds

        </p>

        <table>

          <thead>

            <tr>

              <th>
                Port
              </th>

              <th>
                State
              </th>

              <th>
                Service
              </th>

              <th>
                Version
              </th>

              <th>
                Risk
              </th>

              <th>
                Recommendation
              </th>

            </tr>

          </thead>

          <tbody>

            ${rows}

          </tbody>

        </table>

      </body>

      </html>
    `;

    const blob =
      new Blob(
        [html],
        {
          type: "text/html",
        }
      );

    const url =
      URL.createObjectURL(
        blob
      );

    const link =
      document.createElement(
        "a"
      );

    link.href = url;

    link.download =
      `port-scan-${target}.html`;

    document.body.appendChild(
      link
    );

    link.click();

    document.body.removeChild(
      link
    );

    URL.revokeObjectURL(
      url
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
      setMessage(
        "Please perform a scan first."
      );

      return;
    }

    const doc =
      new jsPDF();

    doc.setFontSize(
      18
    );

    doc.text(
      "Port Scanner Report",
      14,
      20
    );

    doc.setFontSize(
      11
    );

    doc.text(
      `Target: ${target}`,
      14,
      30
    );

    doc.text(
      `Scan Duration: ${
        scanDuration || "-"
      } seconds`,
      14,
      37
    );

    const tableData =
      results.map(
        (item) => [
          item.port ?? "-",
          item.state ?? "-",
          item.service ?? "-",
          item.version ?? "-",
          item.risk ?? "-",
          item.recommendation ?? "-",
        ]
      );

    autoTable(
      doc,
      {
        startY: 45,

        head: [
          [
            "Port",
            "State",
            "Service",
            "Version",
            "Risk",
            "Recommendation",
          ],
        ],

        body:
          tableData,

        styles: {
          fontSize: 8,
        },
      }
    );

    doc.save(
      `port-scan-${target}.pdf`
    );

    setMessage(
      "PDF report downloaded successfully."
    );
  };

  // ============================================================
  // EMAIL REPORT
  // ============================================================

  const sendEmailReport =
    async () => {

      if (!results.length) {
        setMessage(
          "Please perform a scan first."
        );

        return;
      }

      if (
        !recipientEmail.trim()
      ) {
        setMessage(
          "Please enter a recipient email."
        );

        return;
      }

      if (
        !recipientEmail.includes("@")
      ) {
        setMessage(
          "Please enter a valid email address."
        );

        return;
      }

      setMessage(
        "Sending email report..."
      );

      try {

        const response =
          await fetch(
            `${API_URL}/email-report`,
            {
              method: "POST",

              headers:
                authHeaders(),

              body:
                JSON.stringify({
                  recipient:
                    recipientEmail.trim(),

                  target:
                    target,

                  results:
                    results,

                  scan_duration:
                    scanDuration,
                }),
            }
          );

        // ------------------------------------------------------
        // TOKEN ERROR
        // ------------------------------------------------------

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

        const data =
          await response.json();

        if (!response.ok) {

          console.error(
            "Email error:",
            data
          );

          setMessage(
            data.details ||
              data.error ||
              "Failed to send email report."
          );

          return;
        }

        setMessage(
          `Email report sent successfully to ${recipientEmail}.`
        );

        setRecipientEmail("");

      } catch (error) {

        console.error(
          "Email error:",
          error
        );

        setMessage(
          "Unable to send email report. Check backend."
        );
      }
    };

  // ============================================================
  // LOGIN PAGE
  // ============================================================

  if (!token) {

    return (

      <div className="app">

        <div className="auth-container">

          <h1>
            Port Scanner
          </h1>

          <h2>

            {authMode === "login"
              ? "Login"
              : "Register"}

          </h2>

          <form
            onSubmit={
              handleAuth
            }
          >

            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) =>
                setUsername(
                  e.target.value
                )
              }
            />

            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) =>
                setPassword(
                  e.target.value
                )
              }
            />

            <button
              type="submit"
            >

              {authMode === "login"
                ? "Login"
                : "Register"}

            </button>

          </form>

          <button
            className="secondary-button"
            onClick={() =>
              setAuthMode(
                authMode === "login"
                  ? "register"
                  : "login"
              )
            }
          >

            {authMode === "login"
              ? "Create Account"
              : "Back to Login"}

          </button>

          {message && (

            <p className="message">
              {message}
            </p>

          )}

        </div>

      </div>

    );
  }

  // ============================================================
  // MAIN APPLICATION
  // ============================================================

  return (

    <div className="app">

      {/* ======================================================
          HEADER
      ====================================================== */}

      <header className="header">

        <div>

          <h1>
            Port Scanner
          </h1>

          <p>
            Network Security Scanner
          </p>

        </div>

        <div className="user-section">

          <span>
            Welcome, {loggedInUser}
          </span>

          <button
            onClick={
              handleLogout
            }
          >
            Logout
          </button>

        </div>

      </header>

      <main className="container">

        {/* ====================================================
            SCAN SECTION
        ==================================================== */}

        <section className="card">

          <h2>
            Scan Target
          </h2>

          <div className="scan-input">

            <input
              type="text"
              placeholder="Enter IP address or domain"
              value={target}
              onChange={(e) =>
                setTarget(
                  e.target.value
                )
              }
              onKeyDown={(e) => {

                if (
                  e.key === "Enter"
                ) {
                  scanTarget();
                }

              }}
            />

            <button
              onClick={
                scanTarget
              }
              disabled={loading}
            >

              {loading
                ? "Scanning..."
                : "Start Scan"}

            </button>

          </div>

          {message && (

            <p className="message">
              {message}
            </p>

          )}

        </section>

        {/* ====================================================
            RESULTS
        ==================================================== */}

        {results.length > 0 && (

          <section className="card">

            <div className="section-header">

              <div>

                <h2>
                  Scan Results
                </h2>

                <p>
                  Target: {target}
                </p>

                <p>
                  Scan Duration:{" "}
                  {scanDuration || "-"} seconds
                </p>

              </div>

              <span>
                {results.length} result(s)
              </span>

            </div>

            <div className="table-container">

              <table>

                <thead>

                  <tr>

                    <th>
                      Port
                    </th>

                    <th>
                      State
                    </th>

                    <th>
                      Service
                    </th>

                    <th>
                      Version
                    </th>

                    <th>
                      Risk
                    </th>

                    <th>
                      Recommendation
                    </th>

                    <th>
                      CVE
                    </th>

                  </tr>

                </thead>

                <tbody>

                  {results.map(
                    (
                      item,
                      index
                    ) => (

                      <tr
                        key={index}
                      >

                        <td>
                          {item.port ?? "-"}
                        </td>

                        <td>
                          {item.state ?? "-"}
                        </td>

                        <td>
                          {item.service ?? "-"}
                        </td>

                        <td>
                          {item.version ?? "-"}
                        </td>

                        {/* ==================================
                            RISK BADGE
                        ================================== */}

                        <td>

                          <span
                            className={`risk-badge ${
                              String(
                                item.risk ||
                                  "unknown"
                              )
                                .toLowerCase()
                                .includes(
                                  "high"
                                )
                                ? "high"
                                : String(
                                    item.risk ||
                                      ""
                                  )
                                    .toLowerCase()
                                    .includes(
                                      "medium"
                                    )
                                ? "medium"
                                : String(
                                    item.risk ||
                                      ""
                                  )
                                    .toLowerCase()
                                    .includes(
                                      "low"
                                    )
                                ? "low"
                                : "unknown"
                            }`}
                          >

                            {item.risk ??
                              "Unknown"}

                          </span>

                        </td>

                        <td>

                          {item.recommendation ??
                            "-"}

                        </td>

                        {/* ==================================
                            CVE
                        ================================== */}

                        <td>

                          {item.cves &&
                          item.cves.length >
                            0 ? (

                            <div>

                              {item.cves.map(
                                (
                                  cve,
                                  cveIndex
                                ) => (

                                  <div
                                    key={
                                      cveIndex
                                    }
                                  >

                                    <strong>
                                      {
                                        cve.cve_id
                                      }
                                    </strong>

                                    {cve.cvss_score !==
                                      null &&
                                      cve.cvss_score !==
                                        undefined && (

                                        <span>

                                          {" "}
                                          (
                                          {
                                            cve.cvss_score
                                          }
                                          )

                                        </span>

                                      )}

                                  </div>

                                )
                              )}

                            </div>

                          ) : (

                            "No CVE found"

                          )}

                        </td>

                      </tr>

                    )
                  )}

                </tbody>

              </table>

            </div>

            {/* ==================================================
                REPORT BUTTONS
            ================================================== */}

            <div className="report-buttons">

              <button
                onClick={
                  generateHTMLReport
                }
              >
                Generate HTML Report
              </button>

              <button
                onClick={
                  downloadPDF
                }
              >
                Download PDF
              </button>

            </div>

            {/* ==================================================
                EMAIL REPORT
            ================================================== */}

            <div className="email-report-section">

              <h3>
                Email Report
              </h3>

              <div className="email-input-row">

                <input
                  type="email"
                  placeholder="Enter recipient email"
                  value={
                    recipientEmail
                  }
                  onChange={(e) =>
                    setRecipientEmail(
                      e.target.value
                    )
                  }
                />

                <button
                  onClick={
                    sendEmailReport
                  }
                >
                  Email Report
                </button>

              </div>

            </div>

          </section>

        )}

        {/* ====================================================
            SUPABASE SCAN HISTORY
        ==================================================== */}

        <section className="card">

          <div className="section-header">

            <h2>
              Scan History
            </h2>

            {history.length >
              0 && (

              <button
                onClick={
                  clearAllHistory
                }
              >
                Delete All
              </button>

            )}

          </div>

          {history.length === 0 ? (

            <p>
              No scan history available.
            </p>

          ) : (

            <div className="history-list">

              {history.map(
                (
                  item,
                  index
                ) => (

                  <div
                    className="history-item"
                    key={
                      item.id ??
                      index
                    }
                  >

                    <div>

                      <strong>
                        {item.target}
                      </strong>

                      <p>

                        {item.created_at
                          ? new Date(
                              item.created_at
                            ).toLocaleString()
                          : "Unknown date"}

                      </p>

                      <p>

                        Duration:{" "}

                        {item.scan_duration ??
                          "-"}{" "}

                        seconds

                      </p>

                    </div>

                    <div className="history-actions">

                      <button
                        onClick={() =>
                          loadHistoryItem(
                            item
                          )
                        }
                      >
                        View Scan
                      </button>

                      <button
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
              )}

            </div>

          )}

        </section>

      </main>

    </div>

  );
}

export default App;
