
// ==========================================
// REPOSHIELD - FRONTEND APPLICATION
// Connected to FastAPI Backend
// ==========================================

const API_URL = "/api/scan";
const MAX_FILE_SIZE = 20 * 1024 * 1024;

// Current scan data
let findings = [];
let scanHistory = [];
let reports = [];
let currentScan = null;

// ==========================================
// HELPER FUNCTIONS
// ==========================================

function getElement(id) {
    return document.getElementById(id);
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getFindingValue(finding, keys, fallback = "Unknown") {
    for (const key of keys) {
        if (finding[key] !== undefined && finding[key] !== null) {
            return finding[key];
        }
    }
    return fallback;
}

function getIssue(finding) {
    return getFindingValue(
        finding,
        ["issue", "title", "type", "message", "description"]
    );
}

function getSeverity(finding) {
    return String(getFindingValue(finding, ["severity"], "Unknown"));
}

function getFile(finding) {
    return getFindingValue(finding, ["file", "file_path", "path"]);
}

function getLine(finding) {
    return getFindingValue(finding, ["line", "line_number"], "-");
}

function getScanner(finding) {
    return getFindingValue(
        finding,
        ["scanner", "scanner_name", "source"]
    );
}

function severityBadge(severity) {
    const allowed = ["Critical", "High", "Medium", "Low"];
    const original = String(severity);
    const cssSeverity = allowed.find(
        item => item.toLowerCase() === original.toLowerCase()
    );

    const cssClass = cssSeverity || "Unknown";

    return `
        <span class="severity sev-${cssClass}">
            ${escapeHTML(original)}
        </span>
    `;
}

function formatDate(date) {
    return new Date(date).toLocaleString();
}

function countSeverity(level) {
    return findings.filter(
        item => getSeverity(item).toLowerCase() === level.toLowerCase()
    ).length;
}


// ==========================================
// INDIVIDUAL SCANNER PAGES
// ==========================================

function updateScannerPage(prefix, scannerNames, data) {
    const scannerFindings = findings.filter(item =>
        scannerNames.includes(
            String(getScanner(item)).toLowerCase()
        )
    );

    const relevantErrors = (data?.scanner_errors || []).filter(error =>
        scannerNames.includes(
            String(error.scanner).toLowerCase()
        )
    );

    const relevantSkipped = (data?.skipped_scanners || []).filter(name =>
        scannerNames.includes(String(name).toLowerCase())
    );

    // Update severity counts
    const counts = {
        total: scannerFindings.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    scannerFindings.forEach(item => {
        const severity = getSeverity(item).toLowerCase();

        if (Object.prototype.hasOwnProperty.call(counts, severity)) {
            counts[severity]++;
        }
    });

    Object.entries(counts).forEach(([level, value]) => {
        const element = getElement(`${prefix}-${level}`);

        if (element) {
            element.textContent = value;
        }
    });

    // Display findings
    const table = getElement(`${prefix}-findings`);

    if (table) {
        if (scannerFindings.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="5">No findings to display.</td>
                </tr>
            `;
        } else {
            table.innerHTML = scannerFindings.map(item => `
                <tr>
                    <td>${escapeHTML(getIssue(item))}</td>
                    <td>${severityBadge(getSeverity(item))}</td>
                    <td>${escapeHTML(getFile(item))}</td>
                    ${prefix === "docker"
                        ? `<td>${escapeHTML(getScanner(item))}</td>`
                        : `<td>${escapeHTML(getLine(item))}</td>`
                    }
                </tr>
            `).join("");
        }
    }

    // Display scanner status
    const statusElement = getElement(`${prefix}-status`);

    if (statusElement) {
        if (!data) {
            statusElement.textContent =
                "Run a repository scan to see findings.";
        } else if (relevantErrors.length > 0) {
            statusElement.textContent =
                "Scanner error: " +
                relevantErrors.map(error =>
                    `${error.scanner}: ${error.error}`
                ).join(" | ");
        } else if (relevantSkipped.length > 0) {
            statusElement.textContent =
                scannerFindings.length +
                " finding(s) detected. Some scanners were skipped: " +
                relevantSkipped.join(", ");
        } else if (scannerFindings.length === 0) {
            statusElement.textContent =
                "Scan completed successfully. No findings detected.";
        } else {
            statusElement.textContent =
                scannerFindings.length +
                " security finding(s) detected.";
        }
    }
}

function updateAllScannerPages(data) {

    // Secret scanner
    updateScannerPage(
        "secrets",
        ["secret scanner"],
        data
    );

    // Dockerfile and Docker Compose scanners
    updateScannerPage(
        "docker",
        ["docker scanner", "compose scanner"],
        data
    );

    // GitHub Actions workflow scanner
    updateScannerPage(
        "github",
        ["workflow scanner"],
        data
    );
}


// ==========================================
// NAVIGATION
// ==========================================

const pageNames = {
    dashboard: "Dashboard",
    scan: "Scan Repository",
    results: "Vulnerabilities",
    finding: "Finding details",
    reports: "Reports",
    secrets: "Secrets",
    docker: "Docker Security",
    github: "GitHub Actions",
    settings: "Settings"
};

function showPage(page) {
    document.querySelectorAll(".page").forEach(section => {
        section.classList.remove("active");
    });

    const selectedPage = getElement("page-" + page);

    if (!selectedPage) return;

    selectedPage.classList.add("active");

    const breadcrumb = getElement("breadcrumb");

    if (breadcrumb) {
        breadcrumb.textContent = pageNames[page] || page;
    }

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.page === page
        );
    });

    window.scrollTo(0, 0);
}

document.addEventListener("click", function(event) {
    const navButton = event.target.closest("[data-page]");
    if (navButton) showPage(navButton.dataset.page);

    const goButton = event.target.closest("[data-go]");
    if (goButton) showPage(goButton.dataset.go);

    const findingButton = event.target.closest("[data-finding]");
    if (findingButton) showPage("finding");

    const downloadButton = event.target.closest("[data-download]");
    if (downloadButton) {
        downloadReport(
            downloadButton.dataset.download,
            Number(downloadButton.dataset.index)
        );
    }
});

// ==========================================
// DASHBOARD FINDINGS
// ==========================================

function loadDashboardFindings() {
    const table = getElement("dashboard-findings");
    if (!table) return;

    if (findings.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="5">No security findings yet. Scan a repository to get started.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = findings.slice(0, 4).map(item => `
        <tr>
            <td>${escapeHTML(getIssue(item))}</td>
            <td>${severityBadge(getSeverity(item))}</td>
            <td>${escapeHTML(getFile(item))}</td>
            <td>${escapeHTML(getScanner(item))}</td>
            <td>
                <button class="row-action" data-finding>View →</button>
            </td>
        </tr>
    `).join("");
}

// ==========================================
// ALL SCAN RESULTS
// ==========================================

function loadResults() {
    const table = getElement("results-findings");
    if (!table) return;

    if (findings.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="5">No vulnerabilities found. Upload a repository and run a scan.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = findings.map(item => `
        <tr>
            <td>${escapeHTML(getIssue(item))}</td>
            <td>${severityBadge(getSeverity(item))}</td>
            <td>${escapeHTML(getFile(item))}</td>
            <td>${escapeHTML(getLine(item))}</td>
            <td>
                <button class="row-action" data-finding>View details</button>
            </td>
        </tr>
    `).join("");
}

// ==========================================
// DASHBOARD AND RESULTS METRICS
// ==========================================

function updateDashboardMetrics(data) {
    const score = data.security_score ?? "--";
    const total = data.total_findings ?? findings.length;

    const metrics = {
        securityScore: score,
        criticalIssues: countSeverity("critical"),
        highIssues: countSeverity("high"),
        totalFindings: total,

        resultScore: score,
        resultCritical: countSeverity("critical"),
        resultHigh: countSeverity("high"),
        resultMedium: countSeverity("medium"),
        resultLow: countSeverity("low")
    };

    Object.entries(metrics).forEach(([id, value]) => {
        const element = getElement(id);
        if (element) element.textContent = value;
    });
}

// ==========================================
// SCAN HISTORY
// ==========================================

function loadHistory() {
    const container = getElement("recent-history");
    if (!container) return;

    if (scanHistory.length === 0) {
        container.innerHTML = `
            <p>No previous scans. Your scan history will appear here.</p>
        `;
        return;
    }

    container.innerHTML = scanHistory.map(scan => `
        <div class="history-row">
            <strong>${escapeHTML(scan.repository)}</strong>
            <small>${escapeHTML(scan.date)}</small>
            <span>${scan.total} findings</span>
            <b>${escapeHTML(scan.score)}</b>
        </div>
    `).join("");
}

// ==========================================
// REPORTS
// ==========================================

function updateReportSummary() {
    const reportCount = getElement("reportCount");
    const repositoryCount = getElement("repositoryCount");
    const latestScanDate = getElement("latestScanDate");

    if (reportCount) {
        reportCount.textContent = scanHistory.length;
    }

    if (repositoryCount) {
        repositoryCount.textContent =
            new Set(scanHistory.map(scan => scan.repository)).size;
    }

    if (latestScanDate) {
        latestScanDate.textContent =
            scanHistory.length > 0 ? scanHistory[0].date : "--";
    }
}

function loadReports(search = "") {
    const table = getElement("reports-table");
    if (!table) return;

    const filteredReports = reports.filter(report =>
        report.repository.toLowerCase().includes(search.toLowerCase())
    );

    if (filteredReports.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="5">No reports available yet. Complete a scan first.</td>
            </tr>
        `;
        return;
    }

    table.innerHTML = filteredReports.map(report => {
        const index = reports.indexOf(report);

        return `
            <tr>
                <td>${escapeHTML(report.repository)}</td>
                <td>${escapeHTML(report.date)}</td>
                <td>${report.total} findings</td>
                <td>${escapeHTML(report.score)}</td>
                <td>
                    <button class="download-btn"
                        data-download="json"
                        data-index="${index}">
                        Download JSON
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

const reportSearch = getElement("report-search");

if (reportSearch) {
    reportSearch.addEventListener("input", function() {
        loadReports(this.value);
    });
}

// ==========================================
// ZIP FILE UPLOAD
// ==========================================

const fileInput = getElement("zip-file");
const dropZone = getElement("drop-zone");

function showSelectedFile(file) {
    if (!file || !fileInput) return;

    if (!file.name.toLowerCase().endsWith(".zip")) {
        alert("Please select a ZIP file.");
        fileInput.value = "";
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        alert("Maximum ZIP file size is 20 MB.");
        fileInput.value = "";
        return;
    }

    const uploadTitle = getElement("upload-title");
    const selectedFile = getElement("selected-file");

    if (uploadTitle) {
        uploadTitle.textContent = file.name;
    }

    if (selectedFile) {
        selectedFile.textContent =
            file.name + " · " +
            (file.size / 1024 / 1024).toFixed(2) +
            " MB · Ready to scan";
    }
}

if (fileInput) {
    fileInput.addEventListener("change", function() {
        showSelectedFile(this.files[0]);
    });
}

// ==========================================
// DRAG AND DROP
// ==========================================

if (dropZone && fileInput) {
    dropZone.addEventListener("dragover", function(event) {
        event.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", function() {
        dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", function(event) {
        event.preventDefault();
        dropZone.classList.remove("dragover");

        const file = event.dataTransfer.files[0];

        if (file) {
            showSelectedFile(file);

            if (file.name.toLowerCase().endsWith(".zip") &&
                file.size <= MAX_FILE_SIZE) {
                const transfer = new DataTransfer();
                transfer.items.add(file);
                fileInput.files = transfer.files;
            }
        }
    });
}

// ==========================================
// BACKEND SCAN
// ==========================================

const scanButton = getElement("scan-button");

if (scanButton) {
    scanButton.addEventListener("click", async function() {
        const status = getElement("scan-status");
        const file = fileInput?.files[0];

        if (!file) {
            if (status) status.textContent = "Please select a ZIP file first.";
            return;
        }

        if (!file.name.toLowerCase().endsWith(".zip")) {
            if (status) status.textContent = "Please upload a ZIP file.";
            return;
        }

        if (file.size > MAX_FILE_SIZE) {
            if (status) status.textContent = "ZIP file must be 20 MB or smaller.";
            return;
        }

        const formData = new FormData();
        formData.append("file", file);

        if (status) status.textContent = "Scanning repository. Please wait...";

        scanButton.disabled = true;

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Backend scan failed.");
            }

            findings = Array.isArray(data.findings) ? data.findings : [];
            updateAllScannerPages(data);

            currentScan = {
                repository: file.name,
                date: formatDate(new Date()),
                total: data.total_findings ?? findings.length,
                score: data.security_score ?? "--",
                status: data.status,
                findings: findings,
                scannerErrors: data.scanner_errors || []
            };

            scanHistory.unshift(currentScan);
            reports.unshift(currentScan);

            loadDashboardFindings();
            loadResults();
            loadHistory();
            loadReports();
            updateDashboardMetrics(data);
            updateReportSummary();

            const successBanner = getElement("scan-success");

            if (successBanner) {
                successBanner.hidden = false;
                successBanner.textContent =
                    data.status === "completed"
                        ? "Scan completed successfully."
                        : "Scan completed with some scanner errors.";
            }

            const subtitle = getElement("results-subtitle");

            if (subtitle) {
                subtitle.textContent =
                    file.name + " · " + currentScan.total + " findings";
            }

            if (status) {
                status.textContent =
                    data.status === "completed"
                        ? "Scan completed successfully!"
                        : "Scan completed with some scanner errors.";
            }

            showPage("results");

            console.log("Backend scan response:", data);

        } catch (error) {
            console.error("Scan error:", error);

            if (status) {
                status.textContent = "Scan failed: " + error.message;
            }

            const successBanner = getElement("scan-success");
            if (successBanner) successBanner.hidden = true;

        } finally {
            scanButton.disabled = false;
        }
    });
}

// ==========================================
// DOWNLOAD REPORTS
// ==========================================

function downloadReport(type, index) {
    const report = reports[index];
    if (!report) return;

    const data = {
        repository: report.repository,
        scan_date: report.date,
        total_findings: report.total,
        security_score: report.score,
        status: report.status,
        findings: report.findings,
        scanner_errors: report.scannerErrors
    };

    if (type === "json") {
        const blob = new Blob(
            [JSON.stringify(data, null, 2)],
            { type: "application/json" }
        );

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download = report.repository + "-report.json";
        link.click();

        URL.revokeObjectURL(url);
    } else if (type === "pdf") {
        window.print();
    }
}

// ==========================================
// INITIALIZE EMPTY DASHBOARD
// ==========================================

function initializeDashboard() {
    findings = [];
    scanHistory = [];
    reports = [];
    currentScan = null;

    loadDashboardFindings();
    loadResults();
    loadHistory();
    loadReports();
    updateDashboardMetrics({
        security_score: "--",
        total_findings: 0
    });
    updateReportSummary();
}

initializeDashboard();
updateAllScannerPages(null);