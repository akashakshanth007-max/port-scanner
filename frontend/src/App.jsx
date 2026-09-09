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
  const [authMode, setAuthMode] = useState("login");

  const [token, setToken] = useState(
    localStorage.getItem("access_token") || ""
  );

  const [loggedInUser, setLoggedInUser] = useState(
    localStorage.getItem("username") || ""
  );


  // ============================================================
  // DASHBOARD
  // ============================================================

  const [activePage, setActivePage] =
    useState("dashboard");


  // ============================================================
  // SCAN
  // ============================================================

  const [target, setTarget] = useState("");

  const [results, setResults] =
    useState([]);

  const [history, setHistory] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  const [message, setMessage] =
    useState("");

  const [scanDuration, setScanDuration] =
    useState("");


  // ============================================================
  // SCAN OPTIONS
  // ============================================================

  const [showScanOptions, setShowScanOptions] =
    useState(false);

  const [selectedOptions, setSelectedOptions] =
    useState([]);


  const scanOptions = [

    {
      id: "tcp",
      label: "TCP Scan"
    },

    {
      id: "udp",
      label: "UDP Scan"
    },

    {
      id: "syn",
      label: "SYN Scan"
    },

    {
      id: "service",
      label: "Service Version Detection"
    },

    {
      id: "os",
      label: "OS Detection"
    },

    {
      id: "aggressive",
      label: "Aggressive Scan"
    }

  ];


  // ============================================================
  // EMAIL
  // ============================================================

  const [recipientEmail, setRecipientEmail] =
    useState("");


  // ============================================================
  // TOKEN
  // ============================================================

  const getToken = () => {

    return (
      localStorage.getItem("access_token") ||
      token
    );

  };


  // ============================================================
  // AUTH HEADERS
  // ============================================================

  const authHeaders = () => {

    const currentToken =
      getToken();

    return {

      "Content-Type":
        "application/json",

      Authorization:
        `Bearer ${currentToken}`

    };

  };


  // ============================================================
  // TOGGLE SCAN OPTION
  // ============================================================

  const toggleScanOption = (optionId) => {

    setSelectedOptions(
      (previousOptions) => {

        if (
          previousOptions.includes(
            optionId
          )
        ) {

          return previousOptions.filter(
            (item) =>
              item !== optionId
          );

        }

        return [
          ...previousOptions,
          optionId
        ];

      }
    );

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

      const currentToken =
        getToken();

      if (!currentToken) {

        return;

      }


      const response =
        await fetch(
          `${API_URL}/history`,
          {

            method: "GET",

            headers: {

              Authorization:
                `Bearer ${currentToken}`

            }

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


      const data =
        await response.json();


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

    }

    catch (error) {

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

  const handleAuth =
    async (e) => {

      e.preventDefault();

      setMessage("");


      const endpoint =

        authMode === "login"

          ? "/login"

          : "/register";


      try {

        const response =
          await fetch(
            `${API_URL}${endpoint}`,
            {

              method: "POST",

              headers: {

                "Content-Type":
                  "application/json"

              },

              body:
                JSON.stringify({

                  username,
                  password

                })

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


        // REGISTER

        if (
          authMode === "register"
        ) {

          setMessage(
            "Registration successful. Please login."
          );

          setAuthMode(
            "login"
          );

          setPassword("");

          return;

        }


        // LOGIN

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


      }

      catch (error) {

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

    setSelectedOptions([]);

    setShowScanOptions(false);

    setActivePage("dashboard");


    setMessage(
      "Logged out successfully."
    );

  };


  // ============================================================
  // SCAN TARGET
  // ============================================================

  const scanTarget =
    async () => {


      if (!target.trim()) {

        setMessage(
          "Please enter an IP address or domain."
        );

        return;

      }


      if (
        selectedOptions.length === 0
      ) {

        setMessage(
          "Please select at least one scanning option."
        );

        return;

      }


      const currentToken =
        getToken();


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

        const response =
          await fetch(
            `${API_URL}/scan`,
            {

              method: "POST",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${currentToken}`

              },


              body:
                JSON.stringify({

                  target:
                    target.trim(),

                  scan_options:
                    selectedOptions

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


        const data =
          await response.json();


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


        // RESULTS

        const scanResults =
          data.results || [];


        setResults(
          scanResults
        );


        // DURATION

        const duration =

          data.scan_duration ??

          "-";


        setScanDuration(
          duration
        );


        // REFRESH HISTORY

        await loadHistory();


        setMessage(
          `Scan completed successfully. ${scanResults.length} result(s) found.`
        );


        // GO TO RESULTS

        setActivePage(
          "results"
        );


      }

      catch (error) {

        console.error(
          "Scan error:",
          error
        );

        setMessage(
          "Unable to connect to backend."
        );

      }

      finally {

        setLoading(false);

      }

    };


  // ============================================================
  // LOAD HISTORY ITEM
  // ============================================================

  const loadHistoryItem =
    (item) => {


      setTarget(
        item.target || ""
      );


      let savedResults =
        item.results || [];


      if (
        typeof savedResults ===
        "string"
      ) {

        try {

          savedResults =
            JSON.parse(
              savedResults
            );

        }

        catch {

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


      setActivePage(
        "results"
      );


      setMessage(
        "Previous scan loaded."
      );

    };


  // ============================================================
  // DELETE ONE HISTORY
  // ============================================================

  const deleteHistoryItem =
    async (item) => {


      const confirmDelete =
        window.confirm(
          "Delete this scan history?"
        );


      if (!confirmDelete) {

        return;

      }


      try {

        const currentToken =
          getToken();


        if (!currentToken) {

          setMessage(
            "Please login again."
          );

          return;

        }


        const response =
          await fetch(
            `${API_URL}/history/${item.id}`,
            {

              method:
                "DELETE",

              headers: {

                Authorization:
                  `Bearer ${currentToken}`

              }

            }
          );


        const data =
          await response.json();


        if (!response.ok) {

          setMessage(

            data.error ||

            "Failed to delete scan history."

          );

          return;

        }


        await loadHistory();


        setMessage(
          "Scan history deleted successfully."
        );


      }

      catch (error) {

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

  const clearAllHistory =
    async () => {


      const confirmDelete =
        window.confirm(
          "Delete all scan history?"
        );


      if (!confirmDelete) {

        return;

      }


      try {

        const currentToken =
          getToken();


        if (!currentToken) {

          return;

        }


        const response =
          await fetch(
            `${API_URL}/history`,
            {

              method:
                "DELETE",

              headers: {

                Authorization:
                  `Bearer ${currentToken}`

              }

            }
          );


        const data =
          await response.json();


        if (!response.ok) {

          setMessage(

            data.error ||

            "Failed to delete all history."

          );

          return;

        }


        setHistory([]);


        setMessage(
          "All scan history deleted successfully."
        );


      }

      catch (error) {

        console.error(
          "Delete all history error:",
          error
        );


        setMessage(
          "Unable to delete all history."
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


    const rows =

      results

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

            font-family:
              Arial,
              sans-serif;

            margin: 40px;

          }

          table {

            width: 100%;

            border-collapse:
              collapse;

          }

          th,
          td {

            border:
              1px solid #ccc;

            padding:
              10px;

          }

          th {

            background:
              #f2f2f2;

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

      </body>

      </html>

    `;


    const blob =
      new Blob(
        [html],
        {
          type:
            "text/html"
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


    doc.setFontSize(18);


    doc.text(
      "Port Scanner Report",
      14,
      20
    );


    doc.setFontSize(11);


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

          item.recommendation ?? "-"

        ]

      );


    autoTable(
      doc,
      {

        startY:
          45,


        head: [

          [

            "Port",

            "State",

            "Service",

            "Version",

            "Risk",

            "Recommendation"

          ]

        ],


        body:
          tableData,


        styles: {

          fontSize:
            8

        }

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
  // XML REPORT
  // ============================================================

  const downloadXML = () => {


    if (!results.length) {

      setMessage(
        "Please perform a scan first."
      );

      return;

    }


    let xml =

`<?xml version="1.0" encoding="UTF-8"?>

<portScannerReport>

  <target>
    ${target}
  </target>

  <scanDuration>
    ${scanDuration}
  </scanDuration>

  <results>`;


    results.forEach(
      (item) => {

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

      <recommendation>
        ${item.recommendation ?? "-"}
      </recommendation>

    </port>`;

      }
    );


    xml += `

  </results>

</portScannerReport>`;


    const blob =
      new Blob(
        [xml],
        {

          type:
            "application/xml"

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
      `port-scan-${target}.xml`;


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
      "XML report downloaded successfully."
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


      setMessage(
        "Sending email report..."
      );


      try {

        const response =
          await fetch(
            `${API_URL}/email-report`,
            {

              method:
                "POST",


              headers:
                authHeaders(),


              body:
                JSON.stringify({

                  recipient:
                    recipientEmail.trim(),

                  target,

                  results,

                  scan_duration:
                    scanDuration

                })

            }
          );


        const data =
          await response.json();


        if (!response.ok) {

          setMessage(

            data.error ||

            "Failed to send email report."

          );

          return;

        }


        setMessage(
          `Email report sent successfully to ${recipientEmail}.`
        );


        setRecipientEmail("");


      }

      catch (error) {

        console.error(
          "Email error:",
          error
        );


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

      <div className="login-page">

        <div className="auth-container">

          <div className="auth-logo">

            🛡️

          </div>


          <h1>
            Port Scanner
          </h1>


          <p className="auth-subtitle">
            Network Security Scanner
          </p>


          <h2>

            {
              authMode === "login"

                ? "Welcome Back"

                : "Create Account"
            }

          </h2>


          <form
            onSubmit={handleAuth}
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

              {
                authMode === "login"

                  ? "Login"

                  : "Register"
              }

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

            {
              authMode === "login"

                ? "Create Account"

                : "Back to Login"
            }

          </button>


          {
            message && (

              <p className="message">

                {message}

              </p>

            )
          }


        </div>

      </div>

    );

  }


  // ============================================================
  // DASHBOARD
  // ============================================================

  return (

    <div className="dashboard-layout">


      {/* ======================================================
          SIDEBAR
      ====================================================== */}

      <aside className="sidebar">


        <div className="sidebar-logo">

          <div className="logo-icon">
            🛡️
          </div>


          <div>

            <h2>
              Port Scanner
            </h2>

            <p>
              Security Dashboard
            </p>

          </div>

        </div>


        {/* NAVIGATION */}

        <nav className="sidebar-nav">


          <button

            className={
              activePage === "dashboard"

                ? "nav-item active"

                : "nav-item"
            }

            onClick={() =>
              setActivePage(
                "dashboard"
              )
            }

          >

            <span>
              🏠
            </span>

            Dashboard

          </button>



          <button

            className={
              activePage === "scan"

                ? "nav-item active"

                : "nav-item"
            }

            onClick={() =>
              setActivePage(
                "scan"
              )
            }

          >

            <span>
              🔍
            </span>

            New Scan

          </button>



          <button

            className={
              activePage === "results"

                ? "nav-item active"

                : "nav-item"
            }

            onClick={() =>
              setActivePage(
                "results"
              )
            }

          >

            <span>
              📊
            </span>

            Scan Results


            {
              results.length > 0 && (

                <span className="nav-badge">

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
              setActivePage(
                "history"
              )
            }

          >

            <span>
              📜
            </span>

            Scan History


            {
              history.length > 0 && (

                <span className="nav-badge">

                  {history.length}

                </span>

              )
            }

          </button>


        </nav>


        {/* USER */}

        <div className="sidebar-bottom">


          <div className="sidebar-user">

            <div className="user-avatar">

              {
                loggedInUser
                  .charAt(0)
                  .toUpperCase()
              }

            </div>


            <div>

              <strong>
                {loggedInUser}
              </strong>

              <p>
                Logged In
              </p>

            </div>

          </div>


          <button

            className="logout-button"

            onClick={handleLogout}

          >

            🚪 Logout

          </button>


        </div>


      </aside>


      {/* ======================================================
          MAIN CONTENT
      ====================================================== */}

      <main className="main-content">


        {/* ====================================================
            TOP BAR
        ==================================================== */}

        <div className="topbar">

          <div>

            <h1>

              {
                activePage === "dashboard"
                  ? "Dashboard"

                  : activePage === "scan"
                  ? "New Scan"

                  : activePage === "results"
                  ? "Scan Results"

                  : "Scan History"
              }

            </h1>


            <p>

              Welcome back,
              {" "}
              {loggedInUser}

            </p>

          </div>


          <div className="status-online">

            <span></span>

            System Online

          </div>


        </div>


        {/* ====================================================
            GLOBAL MESSAGE
        ==================================================== */}

        {
          message && (

            <p className="message global-message">

              {message}

            </p>

          )
        }


        {/* ====================================================
            DASHBOARD PAGE
        ==================================================== */}

        {
          activePage === "dashboard" && (

            <>


              <section className="stats-grid">


                <div className="stat-card">

                  <div className="stat-icon">
                    📊
                  </div>

                  <div>

                    <p>
                      Total Scans
                    </p>

                    <h2>
                      {history.length}
                    </h2>

                  </div>

                </div>



                <div className="stat-card">

                  <div className="stat-icon">
                    🔓
                  </div>

                  <div>

                    <p>
                      Open Ports
                    </p>

                    <h2>
                      {results.length}
                    </h2>

                  </div>

                </div>



                <div className="stat-card">

                  <div className="stat-icon">
                    🎯
                  </div>

                  <div>

                    <p>
                      Current Target
                    </p>

                    <h2 className="target-stat">

                      {
                        target || "-"
                      }

                    </h2>

                  </div>

                </div>



                <div className="stat-card">

                  <div className="stat-icon">
                    ⏱️
                  </div>

                  <div>

                    <p>
                      Scan Duration
                    </p>

                    <h2>

                      {
                        scanDuration || "-"
                      }

                    </h2>

                  </div>

                </div>


              </section>


              {/* QUICK ACTIONS */}

              <section className="dashboard-card">

                <h2>
                  Quick Actions
                </h2>


                <div className="quick-actions">


                  <button

                    onClick={() =>
                      setActivePage(
                        "scan"
                      )
                    }

                  >

                    🔍

                    <span>
                      Start New Scan
                    </span>

                  </button>



                  <button

                    onClick={() =>
                      setActivePage(
                        "results"
                      )
                    }

                  >

                    📊

                    <span>
                      View Results
                    </span>

                  </button>



                  <button

                    onClick={() =>
                      setActivePage(
                        "history"
                      )
                    }

                  >

                    📜

                    <span>
                      Scan History
                    </span>

                  </button>


                </div>

              </section>


              {/* RECENT HISTORY */}

              <section className="dashboard-card">

                <div className="section-header">

                  <div>

                    <h2>
                      Recent Scans
                    </h2>

                    <p>
                      Your latest scan activity
                    </p>

                  </div>


                  <button

                    onClick={() =>
                      setActivePage(
                        "history"
                      )
                    }

                  >

                    View All

                  </button>

                </div>


                {
                  history.length === 0

                    ? (

                      <p className="empty-text">

                        No scan history available.

                      </p>

                    )

                    : (

                      <div className="recent-list">

                        {
                          history
                            .slice(0, 5)
                            .map(

                              (
                                item,
                                index
                              ) => (

                                <div

                                  className="recent-item"

                                  key={
                                    item.id ??
                                    index
                                  }

                                >

                                  <div>

                                    <strong>

                                      🎯
                                      {" "}
                                      {item.target}

                                    </strong>


                                    <p>

                                      {
                                        item.created_at

                                          ? new Date(
                                              item.created_at
                                            ).toLocaleString()

                                          : "Unknown date"
                                      }

                                    </p>

                                  </div>


                                  <button

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


              </section>


            </>

          )
        }


        {/* ====================================================
            NEW SCAN PAGE
        ==================================================== */}

        {
          activePage === "scan" && (

            <section className="card scan-card">


              <div className="page-title">

                <div>

                  <h2>
                    🔍 Scan Target
                  </h2>

                  <p>
                    Enter an IP address or domain
                    and select scanning options.
                  </p>

                </div>

              </div>


              <div className="scan-input">


                {/* TARGET */}

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


                {/* OPTIONS */}

                <div className="scan-options-container">


                  <button

                    type="button"

                    className="scan-options-button"

                    onClick={() =>
                      setShowScanOptions(
                        !showScanOptions
                      )
                    }

                  >

                    ⚙ Options

                    {
                      selectedOptions.length > 0

                        ? ` (${selectedOptions.length})`

                        : ""
                    }

                    {" "}

                    {
                      showScanOptions

                        ? "▲"

                        : "▼"
                    }

                  </button>


                  {
                    showScanOptions && (

                      <div className="scan-options-menu">


                        {
                          scanOptions.map(
                            (option) => (

                              <label

                                key={option.id}

                                className="scan-option-item"

                              >

                                <input

                                  type="checkbox"

                                  checked={
                                    selectedOptions.includes(
                                      option.id
                                    )
                                  }

                                  onChange={() =>
                                    toggleScanOption(
                                      option.id
                                    )
                                  }

                                />


                                <span>

                                  {option.label}

                                </span>


                              </label>

                            )
                          )
                        }


                      </div>

                    )
                  }


                </div>


                {/* START SCAN */}

                <button

                  className="start-scan-button"

                  onClick={scanTarget}

                  disabled={loading}

                >

                  {
                    loading

                      ? "Scanning..."

                      : "Start Scan"
                  }

                </button>


              </div>


              {/* SELECTED OPTIONS */}

              {
                selectedOptions.length > 0 && (

                  <div className="selected-options">

                    <strong>

                      Selected Options:

                    </strong>


                    {" "}


                    {
                      scanOptions

                        .filter(

                          (option) =>
                            selectedOptions.includes(
                              option.id
                            )

                        )

                        .map(
                          (option) =>
                            option.label
                        )

                        .join(", ")
                    }


                  </div>

                )
              }


            </section>

          )
        }


        {/* ====================================================
            RESULTS PAGE
        ==================================================== */}

        {
          activePage === "results" && (

            <section className="card results-card">


              <div className="section-header">


                <div>

                  <h2>
                    📊 Scan Results
                  </h2>


                  {
                    results.length > 0 && (

                      <>

                        <p>

                          Target:
                          {" "}
                          <strong>
                            {target}
                          </strong>

                        </p>


                        <p>

                          Scan Duration:
                          {" "}

                          {
                            scanDuration || "-"
                          }

                          {" "}
                          seconds

                        </p>

                      </>

                    )
                  }


                </div>


                {
                  results.length > 0 && (

                    <span>

                      {results.length}
                      {" "}
                      result(s)

                    </span>

                  )
                }


              </div>


              {
                results.length === 0

                  ? (

                    <div className="empty-results">

                      <div>
                        📊
                      </div>


                      <h3>
                        No Scan Results
                      </h3>


                      <p>
                        Start a new scan to view
                        results here.
                      </p>


                      <button

                        onClick={() =>
                          setActivePage(
                            "scan"
                          )
                        }

                      >

                        Start New Scan

                      </button>


                    </div>

                  )

                  : (

                    <>


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

                                      {
                                        item.port ?? "-"
                                      }

                                    </td>


                                    <td>

                                      {
                                        item.state ?? "-"
                                      }

                                    </td>


                                    <td>

                                      {
                                        item.service ?? "-"
                                      }

                                    </td>


                                    <td>

                                      {
                                        item.version ?? "-"
                                      }

                                    </td>


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

                                        {
                                          item.risk ??
                                          "Unknown"
                                        }

                                      </span>


                                    </td>


                                    <td>

                                      {
                                        item.recommendation ??
                                        "-"
                                      }

                                    </td>


                                    <td>


                                      {
                                        item.cves &&
                                        item.cves.length > 0

                                          ? (

                                            <div>

                                              {
                                                item.cves.map(

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


                                                      {
                                                        cve.cvss_score !==
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

                                                        )
                                                      }


                                                    </div>

                                                  )

                                                )
                                              }

                                            </div>

                                          )

                                          : (

                                            "No CVE found"

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


                      {/* REPORTS */}

                      <div className="report-buttons">


                        <button
                          onClick={
                            generateHTMLReport
                          }
                        >

                          🌐 HTML Report

                        </button>


                        <button
                          onClick={
                            downloadPDF
                          }
                        >

                          📄 Download PDF

                        </button>


                        <button
                          onClick={
                            downloadXML
                          }
                        >

                          📁 Download XML

                        </button>


                      </div>


                      {/* EMAIL */}

                      <div className="email-report-section">


                        <h3>
                          📧 Email Report
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

                            Send Email

                          </button>


                        </div>


                      </div>


                    </>

                  )
              }


            </section>

          )
        }


        {/* ====================================================
            HISTORY PAGE
        ==================================================== */}

        {
          activePage === "history" && (

            <section className="card history-card">


              <div className="section-header">


                <div>

                  <h2>
                    📜 Scan History
                  </h2>

                  <p>
                    View and manage your
                    previous scans.
                  </p>

                </div>


                {
                  history.length > 0 && (

                    <button

                      className="delete-all-button"

                      onClick={
                        clearAllHistory
                      }

                    >

                      🗑 Delete All

                    </button>

                  )
                }


              </div>


              {
                history.length === 0

                  ? (

                    <div className="empty-results">


                      <div>
                        📜
                      </div>


                      <h3>
                        No Scan History
                      </h3>


                      <p>
                        Your completed scans will
                        appear here.
                      </p>


                      <button

                        onClick={() =>
                          setActivePage(
                            "scan"
                          )
                        }

                      >

                        Start Your First Scan

                      </button>


                    </div>

                  )

                  : (

                    <div className="history-list">


                      {
                        history.map(

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


                              <div className="history-info">


                                <div className="history-target">

                                  🎯

                                  <strong>

                                    {item.target}

                                  </strong>

                                </div>


                                <p>


                                  🕒


                                  {" "}


                                  {
                                    item.created_at

                                      ? new Date(
                                          item.created_at
                                        ).toLocaleString()

                                      : "Unknown date"
                                  }


                                </p>


                                <p>


                                  ⏱


                                  {" "}


                                  Duration:


                                  {" "}


                                  {
                                    item.scan_duration ??
                                    "-"
                                  }


                                  {" "}


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

                                  👁 View Scan

                                </button>


                                <button

                                  onClick={() =>
                                    deleteHistoryItem(
                                      item
                                    )
                                  }

                                >

                                  🗑 Delete

                                </button>


                              </div>


                            </div>

                          )

                        )
                      }


                    </div>

                  )
              }


            </section>

          )
        }


      </main>


    </div>

  );

}


export default App;
