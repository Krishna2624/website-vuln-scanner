const mongoose = require("mongoose");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const cheerio = require("cheerio");
const sslChecker = require("ssl-checker").default;
const PDFDocument = require("pdfkit");
const dnsModule = require("dns");
const { exec } = require("child_process");
dnsModule.setServers(["8.8.8.8", "1.1.1.1"]);
const PORT = process.env.PORT || 5000;
const dns = dnsModule.promises;
const net = require("net");
require("dotenv").config();
const commonPorts = [
  { port: 21, service: "FTP", risk: "High" },
  { port: 22, service: "SSH", risk: "Medium" },
  { port: 23, service: "Telnet", risk: "Critical" },
  { port: 25, service: "SMTP", risk: "Medium" },
  { port: 53, service: "DNS", risk: "Low" },
  { port: 80, service: "HTTP", risk: "Low" },
  { port: 110, service: "POP3", risk: "Medium" },
  { port: 143, service: "IMAP", risk: "Medium" },
  { port: 443, service: "HTTPS", risk: "Low" },
  { port: 3306, service: "MySQL", risk: "High" },
  { port: 5432, service: "PostgreSQL", risk: "High" },
  { port: 6379, service: "Redis", risk: "High" },
  { port: 8080, service: "HTTP-Alt", risk: "Medium" }
];
const whois = require("whois-json");

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

const scanSchema = new mongoose.Schema({
  userId: String, 
  target: String,
  statusCode: Number,
  pageTitle: String,

  ssl: Object,
  technologies: Object,
  headers: Object,

  findings: Array,
  headerFindings: Array,
  cookieFindings: Array,
  links: Array,
  summary: Object,

  scannedAt: {
    type: Date,
    default: Date.now
  }


});

const dnsLookupSchema = new mongoose.Schema({
   userId: String,
  domain: String,
  inputUrl: String,

  A: [String],
  AAAA: [String],
  MX: Array,
  NS: [String],
  TXT: Array,

  lookedUpAt: {
    type: Date,
    default: Date.now
  }
});
const DNSLookup = mongoose.model("DNSLookup", dnsLookupSchema);

const portScanSchema = new mongoose.Schema({
   userId: String,
  target: String,
  scannedAt: {
    type: Date,
    default: Date.now
  },
      hostInfo: {
      hostname: String,
      os: String,
      latency: String,
      deviceType: String,
      scanTime: Date
    },
  results: [
    {
      port: Number,
      service: String,
      status: String,
      version: String,
      risk: String,
      cveId: String,
      cveSeverity: String,
      cvssScore: String,
      cveDescription: String,
      cveRecommendation: String,
      recommendation: String

    }
  ]
});
const PortScan = mongoose.model("PortScan", portScanSchema);

const whoisSchema = new mongoose.Schema({
   userId: String,
  domain: String,
  resolvedIPs: [String],
  registrar: String,
  creationDate: String,
  expirationDate: String,
  updatedDate: String,
  nameServers: [String],
  status: String,
  country: String,
  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const WhoisScan = mongoose.model("WhoisScan", whoisSchema);

const subdomainSchema = new mongoose.Schema({
   userId: String,
  domain: String,
  subdomains: [String],
  totalFound: Number,
  source: String,
  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const SubdomainScan = mongoose.model("SubdomainScan", subdomainSchema);

const fullScanSchema = new mongoose.Schema({
   userId: String,
  reportType: String,
  target: String,
  domain: String,
  riskScore: Number,
  riskLevel: String,
  scannedAt: {
    type: Date,
    default: Date.now
  },

  website: Object,
  dns: Object,
  ports: Object,
  whois: Object,
  subdomains: Object
});

const daaScanSchema = new mongoose.Schema({
  userId: String,
  target: String,
  domain: String,
  crawlDepth: Number,

  discovery: Object,

  summary: {
    pagesCrawled: Number,
    internalLinks: Number,
    externalLinks: Number,
    formsFound: Number,
    apiEndpoints: Number
  },

  scannedAt: {
    type: Date,
    default: Date.now
  }
});

const dynamicDiscoverySchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,

  pagesDiscovered: [String],
  routesDiscovered: [String],

  formsDiscovered: [
    {
      pageUrl: String,
      action: String,
      method: String,
      inputs: {
        type: [
          {
            name: String,
            inputType: String
          }
        ],
        default: []
      }
    }
  ],

  technologies: [String],
  jsFiles: [String],

  summary: {
    totalPages: Number,
    totalRoutes: Number,
    totalForms: Number,
    totalJsFiles: Number,
    totalTechnologies: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicDiscoveryScan = mongoose.model(
  "DynamicDiscoveryScan",
  dynamicDiscoverySchema
);

const dynamicInputAnalysisSchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,

  parameters: [
    {
      pageUrl: String,
      parameter: String,
      location: String,
      risk: String
    }
  ],

  forms: [
    {
      pageUrl: String,
      action: String,
      method: String,
      inputs: [
        {
          name: String,
          inputType: String,
          risk: String
        }
      ]
    }
  ],

  jsFiles: [String],

  summary: {
    totalParameters: Number,
    totalForms: Number,
    totalInputs: Number,
    hiddenInputs: Number,
    passwordInputs: Number,
    fileInputs: Number,
    jsFiles: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicInputAnalysis = mongoose.model(
  "DynamicInputAnalysis",
  dynamicInputAnalysisSchema
);

const dynamicAuthAssessmentSchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,

  loginForms: Array,
  passwordFields: Number,
  hiddenFields: Number,
  cookieSecurity: Array,
  authFindings: Array,

  summary: {
    loginForms: Number,
    passwordFields: Number,
    hiddenFields: Number,
    cookieIssues: Number,
    totalFindings: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicAuthAssessment = mongoose.model(
  "DynamicAuthAssessment",
  dynamicAuthAssessmentSchema
);

const dynamicSecurityControlsSchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,

  httpsEnabled: Boolean,
  statusCode: Number,

  headers: Object,
  headerChecks: Array,
  cookieSecurity: Array,
  corsReview: Object,
  controlFindings: Array,

  summary: {
    totalControls: Number,
    passedControls: Number,
    failedControls: Number,
    cookieIssues: Number,
    totalFindings: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicSecurityControls = mongoose.model(
  "DynamicSecurityControls",
  dynamicSecurityControlsSchema
);

const dynamicApiSecuritySchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,

  discoveredApis: Array,
  swaggerEndpoints: Array,
  jsonEndpoints: Array,
  corsReview: Object,
  methods: Array,
  apiFindings: Array,

  summary: {
    totalApis: Number,
    swaggerFound: Number,
    jsonEndpoints: Number,
    riskyCors: Number,
    totalFindings: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicApiSecurity = mongoose.model(
  "DynamicApiSecurity",
  dynamicApiSecuritySchema
);

const dynamicVulnerabilityAssessmentSchema = new mongoose.Schema({
  userId: String,
  targetUrl: String,
  mode: String,

  statusCode: Number,
  reflectedParameters: Array,
  sqlErrorIndicators: Array,
  openRedirectIndicators: Array,
  sensitiveFiles: Array,
  uploadRisks: Array,
  jsSecretIndicators: Array,
  dangerousMethods: Array,
  vulnerabilityFindings: Array,

  summary: {
    reflectedParameters: Number,
    sqlErrors: Number,
    openRedirects: Number,
    sensitiveFiles: Number,
    uploadRisks: Number,
    jsSecrets: Number,
    dangerousMethods: Number,
    totalFindings: Number
  },

  riskLevel: String,

  scannedAt: {
    type: Date,
    default: Date.now
  }
});
const DynamicVulnerabilityAssessment = mongoose.model(
  "DynamicVulnerabilityAssessment",
  dynamicVulnerabilityAssessmentSchema
);





const DAAScan = mongoose.model("DAAScan", daaScanSchema);
const FullScan = mongoose.model("FullScan", fullScanSchema);
const Scan = mongoose.model("Scan", scanSchema);
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  }
});
const User = mongoose.model("User", userSchema);




function normalizeUrl(url) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return "https://" + url;
  }
  return url;
}

function checkSecurityHeaders(headers) {
  const required = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
  ];

  return required.map(header => ({
    name: header,
    status: headers[header] ? "Present" : "Missing",
    severity: headers[header] ? "Info" : "Medium",
    value: headers[header] || "Not configured"
  }));
}

function analyzeCookies(setCookieHeaders = []) {
  return setCookieHeaders.map(cookie => ({
    cookie,
    httpOnly: /httponly/i.test(cookie),
    secure: /secure/i.test(cookie),
    sameSite: /samesite/i.test(cookie),
    risk:
      !/httponly/i.test(cookie) || !/secure/i.test(cookie)
        ? "Medium"
        : "Low"
  }));
}

function detectVulnerabilities(headers, url, html) {
  let findings = [];

  // Missing CSP
  if (!headers["content-security-policy"]) {
    findings.push({
      title: "Missing Content Security Policy",
      severity: "High",
      risk: "XSS attacks possible",
      solution: "Implement Content-Security-Policy header"
    });
  }

  // Missing HSTS
  if (!headers["strict-transport-security"]) {
    findings.push({
      title: "Missing HSTS Header",
      severity: "Medium",
      risk: "SSL stripping attack possible",
      solution: "Enable Strict-Transport-Security"
    });
  }

  // Missing X-Frame
  if (!headers["x-frame-options"]) {
    findings.push({
      title: "Clickjacking Protection Missing",
      severity: "Medium",
      risk: "Website vulnerable to clickjacking",
      solution: "Add X-Frame-Options header"
    });
  }

  // Server disclosure
  if (headers["server"]) {
    findings.push({
      title: "Server Information Disclosure",
      severity: "Low",
      risk: "Technology fingerprinting possible",
      solution: "Hide Server header"
    });
  }

  // X-Powered-By disclosure
  if (headers["x-powered-by"]) {
    findings.push({
      title: "Technology Disclosure",
      severity: "Low",
      risk: "Framework disclosure detected",
      solution: "Hide X-Powered-By header"
    });
  }

  // Basic XSS reflection check
  if (html.includes("<script>")) {
    findings.push({
      title: "Potential Script Injection Surface",
      severity: "Medium",
      risk: "Possible XSS attack surface",
      solution: "Validate inputs and sanitize output"
    });
  }

  return findings;
}

async function crawlWebsite(startUrl, maxPages = 10) {
  const visited = new Set();
  const queue = [startUrl];

  const internalLinks = [];
  const externalLinks = [];
  const forms = [];
  const apiEndpoints = [];

  const baseHost = new URL(startUrl).hostname;

  while (queue.length > 0 && visited.size < maxPages) {
    const currentUrl = queue.shift();

    if (visited.has(currentUrl)) continue;
    visited.add(currentUrl);

    try {
      const response = await axios.get(currentUrl, {
        timeout: 10000,
        maxRedirects: 3,
        validateStatus: () => true,
        headers: {
          "User-Agent": "SecurityPlatformCrawler/1.0"
        }
      });

      const html = response.data || "";
      const $ = cheerio.load(html);

      $("a").each((i, el) => {
        const href = $(el).attr("href");
        if (!href) return;

        try {
          const absoluteUrl = new URL(href, currentUrl).href;
          const linkHost = new URL(absoluteUrl).hostname;

          if (linkHost === baseHost) {
            if (!internalLinks.includes(absoluteUrl)) {
              internalLinks.push(absoluteUrl);
            }

            if (!visited.has(absoluteUrl) && queue.length < maxPages) {
              queue.push(absoluteUrl);
            }

            if (
              absoluteUrl.includes("/api/") ||
              absoluteUrl.includes("/graphql") ||
              absoluteUrl.includes("/swagger") ||
              absoluteUrl.includes("/openapi")
            ) {
              apiEndpoints.push(absoluteUrl);
            }

          } else {
            if (!externalLinks.includes(absoluteUrl)) {
              externalLinks.push(absoluteUrl);
            }
          }
        } catch {}
      });

      $("form").each((i, form) => {
        forms.push({
          page: currentUrl,
          action: $(form).attr("action") || currentUrl,
          method: ($(form).attr("method") || "GET").toUpperCase(),
          inputs: $(form)
            .find("input")
            .map((j, input) => ({
              name: $(input).attr("name") || "unnamed",
              type: $(input).attr("type") || "text"
            }))
            .get()
        });
      });

    } catch (error) {
      console.log("Crawler skipped:", currentUrl, error.message);
    }
  }

  return {
    crawledPages: [...visited],
    internalLinks: [...new Set(internalLinks)].slice(0, 50),
    externalLinks: [...new Set(externalLinks)].slice(0, 50),
    forms: forms.slice(0, 25),
    apiEndpoints: [...new Set(apiEndpoints)].slice(0, 25),
    summary: {
      totalPagesCrawled: visited.size,
      internalLinks: internalLinks.length,
      externalLinks: externalLinks.length,
      formsFound: forms.length,
      apiEndpoints: apiEndpoints.length
    }
  };
}

async function runDnsLookupModule(targetUrl) {
  try {
    const domain = new URL(targetUrl).hostname.replace(/^www\./, "");

    const A = await dns.resolve4(domain).catch(() => []);
    const AAAA = await dns.resolve6(domain).catch(() => []);
    const MX = await dns.resolveMx(domain).catch(() => []);
    const NS = await dns.resolveNs(domain).catch(() => []);
    const TXT = await dns.resolveTxt(domain).catch(() => []);

    return {
      domain,
      A,
      AAAA,
      MX,
      NS,
      TXT
    };

  } catch (error) {
    return {
      domain: "DNS lookup failed",
      A: [],
      AAAA: [],
      MX: [],
      NS: [],
      TXT: []
    };
  }
}

function scanPort(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    socket.setTimeout(1200);

    socket.on("connect", () => {
      socket.destroy();
      resolve("Open");
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve("Closed");
    });

    socket.on("error", () => {
      resolve("Closed");
    });

    socket.connect(port, host);
  });
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, "SECRET_KEY");
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

function adminMiddleware(req, res, next) {
  if (req.userRole !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }

  next();
}

function runNmapFullScan(target) {
  return new Promise((resolve, reject) => {
    const command = `nmap -Pn -T4 -sV --top-ports 1000 --open ${target}`;

    exec(command, { timeout: 600000 }, async (error, stdout, stderr) => {
      if (error) {
        return reject(error);
      }

      const lines = stdout.split("\n");

      const results = [];

      const hostInfo = {
        target,
        hostname: "Unknown",
        os: "Unknown",
        latency: "Unknown",
        deviceType: "Unknown",
        scanTime: new Date()
      };

      for (const line of lines) {
                if (line.includes("Host is up")) {
          const latencyMatch = line.match(/\((.*?) latency\)/);

          if (latencyMatch) {
            hostInfo.latency = latencyMatch[1];
          }
        }

        if (line.includes("OS details:")) {
          hostInfo.os = line.replace("OS details:", "").trim();
        }

        if (line.includes("Device type:")) {
          hostInfo.deviceType = line.replace("Device type:", "").trim();
        }

        if (line.includes("Nmap scan report for")) {
          const hostnameMatch = line.replace("Nmap scan report for", "").trim();

          hostInfo.hostname = hostnameMatch;
        }
        const match = line.match(/^(\d+)\/tcp\s+open\s+(\S+)\s*(.*)$/);

        if (match) {
          const port = Number(match[1]);
          const service = match[2];
          const version = match[3] || "Version not detected";

          let cves = await searchNvdCves(service, version, port);

          let cveInfo = cves.length
            ? cves[0]
            : getRealisticCveForService(service, version, port);

          results.push({
            port,
            service,
            status: "Open",
            version,
            risk: cveInfo.cveSeverity || "Medium",
            recommendation:
              cveInfo.cveRecommendation ||
              "Review exposed service and restrict access if not required.",
            ...cveInfo
          });
        }
      }

      resolve({
        hostInfo,
        results
      });
    });
  });
}

async function searchNvdCves(service, version, port) {
  try {
    const keyword = `${service} ${version}`.replace("Version not detected", "").trim();

    if (!keyword || keyword.length < 3) {
      return [];
    }

    const response = await axios.get("https://services.nvd.nist.gov/rest/json/cves/2.0", {
      params: {
        keywordSearch: keyword,
        resultsPerPage: 5,
        noRejected: ""
      },
      timeout: 15000
    });

    const vulnerabilities = response.data.vulnerabilities || [];

    return vulnerabilities.map(item => {
      const cve = item.cve;

      const metrics =
        cve.metrics?.cvssMetricV31?.[0] ||
        cve.metrics?.cvssMetricV30?.[0] ||
        cve.metrics?.cvssMetricV2?.[0];

      return {
        cveId: cve.id || "N/A",
        cveSeverity:
          metrics?.cvssData?.baseSeverity ||
          metrics?.baseSeverity ||
          "Unknown",
        cvssScore:
          metrics?.cvssData?.baseScore ||
          "N/A",
        cveDescription:
          cve.descriptions?.find(d => d.lang === "en")?.value ||
          "No description available.",
        cveRecommendation:
          "Verify affected product version, apply vendor patches, and restrict exposure where possible.",
        source: "NVD"
      };
    });

  } catch (error) {
    console.error("NVD lookup error:", error.message);
    return [];
  }
}

function getRealisticCveForService(service, version, port) {
  const text = `${service} ${version}`.toLowerCase();

  if (text.includes("apache") && text.includes("2.4.49")) {
    return {
      cveId: "CVE-2021-41773",
      cveSeverity: "Critical",
      cvssScore: "9.8",
      cveDescription:
        "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability.",
      cveRecommendation:
        "Upgrade Apache immediately to a patched version."
    };
  }

  if (text.includes("apache") && text.includes("2.4.50")) {
    return {
      cveId: "CVE-2021-42013",
      cveSeverity: "Critical",
      cvssScore: "9.8",
      cveDescription:
        "Apache HTTP Server 2.4.50 path traversal and remote code execution vulnerability.",
      cveRecommendation:
        "Upgrade Apache immediately to a patched version."
    };
  }

  if (text.includes("openssh") && text.includes("8.5")) {
    return {
      cveId: "CVE-2024-6387",
      cveSeverity: "Critical",
      cvssScore: "8.1",
      cveDescription:
        "OpenSSH regreSSHion vulnerability affecting vulnerable OpenSSH versions.",
      cveRecommendation:
        "Upgrade OpenSSH and restrict SSH access to trusted IP addresses."
    };
  }

  if (text.includes("openssh") && text.includes("8.6")) {
    return {
      cveId: "CVE-2024-6387",
      cveSeverity: "Critical",
      cvssScore: "8.1",
      cveDescription:
        "OpenSSH regreSSHion vulnerability affecting vulnerable OpenSSH versions.",
      cveRecommendation:
        "Upgrade OpenSSH and restrict SSH access to trusted IP addresses."
    };
  }

  if (text.includes("mysql")) {
    return {
      cveId: "Review Required",
      cveSeverity: "High",
      cvssScore: "N/A",
      cveDescription:
        "Database service exposed. Version-specific CVE validation required.",
      cveRecommendation:
        "Restrict MySQL exposure and allow access only from trusted hosts."
    };
  }

  if (text.includes("redis")) {
    return {
      cveId: "Review Required",
      cveSeverity: "Critical",
      cvssScore: "N/A",
      cveDescription:
        "Redis service exposed. Public Redis exposure is high risk.",
      cveRecommendation:
        "Do not expose Redis publicly. Bind to localhost or private network."
    };
  }

  if (text.includes("telnet") || port === 23) {
    return {
      cveId: "Insecure Protocol",
      cveSeverity: "Critical",
      cvssScore: "N/A",
      cveDescription:
        "Telnet transmits credentials in clear text.",
      cveRecommendation:
        "Disable Telnet and use SSH instead."
    };
  }
    if (text.includes("microsoft-ds") || text.includes("smb") || port === 445) {
    return {
      cveId: "SMB Exposure Review",
      cveSeverity: "High",
      cvssScore: "N/A",
      cveDescription:
        "SMB service is exposed. SMB has a history of critical vulnerabilities and should not be exposed publicly.",
      cveRecommendation:
        "Restrict SMB to internal networks only and block port 445 from public access."
    };
  }

  if (text.includes("rdp") || port === 3389) {
    return {
      cveId: "RDP Exposure Review",
      cveSeverity: "High",
      cvssScore: "N/A",
      cveDescription:
        "Remote Desktop service exposure increases brute-force and remote access risk.",
      cveRecommendation:
        "Restrict RDP using VPN, firewall rules, and strong authentication."
    };
  }

  if (text.includes("ftp") || port === 21) {
    return {
      cveId: "Insecure Protocol",
      cveSeverity: "Medium",
      cvssScore: "N/A",
      cveDescription:
        "FTP can transmit credentials in clear text.",
      cveRecommendation:
        "Use SFTP or FTPS instead of plain FTP."
    };
  }

  if (text.includes("iis")) {
    return {
      cveId: "IIS Review Required",
      cveSeverity: "Medium",
      cvssScore: "N/A",
      cveDescription:
        "Microsoft IIS detected. Version-specific CVE validation is recommended.",
      cveRecommendation:
        "Apply Windows/IIS updates and disable unnecessary modules."
    };
  }
      if (port === 5040) {
      return {
        cveId: "Windows Service Exposure Review",
        cveSeverity: "Medium",
        cvssScore: "N/A",
        cveDescription:
          "Port 5040 is commonly associated with Windows CDPSvc service exposure.",
        cveRecommendation:
          "Restrict this port with Windows Firewall if not required."
      };
    }

    if (port === 7070 || text.includes("realserver")) {
      return {
        cveId: "RealServer Service Review",
        cveSeverity: "Medium",
        cvssScore: "N/A",
        cveDescription:
          "RealServer/streaming service detected. Version-specific validation is required.",
        cveRecommendation:
          "Verify the service version, patch if outdated, and restrict public access if unnecessary."
      };
    }



    return {
        cveId: "Manual Review Recommended",
        cveSeverity:
          port < 1024 ? "Medium" : "Info",
        cvssScore: "N/A",
        cveDescription:
          `Service detected on port ${port}. No direct local CVE mapping found.`,
        cveRecommendation:
          "Review service version manually and verify against NVD/CVE databases."
      };
}

async function runDynamicDiscovery(targetUrl) {
  const visited = new Set();
  const pages = [];
  const routes = new Set();
  const forms = [];
  const technologies = new Set();
  const jsFiles = new Set();

  const baseUrl = new URL(targetUrl);
  const queue = [targetUrl];

  while (queue.length > 0 && visited.size < 15) {
    const currentUrl = queue.shift();

    if (visited.has(currentUrl)) continue;
    visited.add(currentUrl);

    try {
      const response = await axios.get(currentUrl, {
        timeout: 10000,
        headers: {
          "User-Agent": "SecurityAssessmentBot/1.0"
        }
      });

      const html = response.data;
      const $ = cheerio.load(html);

      pages.push(currentUrl);

      const headers = response.headers;

      if (headers["server"]) technologies.add(headers["server"]);
      if (headers["x-powered-by"]) technologies.add(headers["x-powered-by"]);

      if (html.includes("wp-content")) technologies.add("WordPress");
      if (html.includes("react")) technologies.add("React");
      if (html.includes("angular")) technologies.add("Angular");
      if (html.includes("vue")) technologies.add("Vue.js");
      if (html.includes("jquery")) technologies.add("jQuery");

      $("script[src]").each((i, el) => {
        const src = $(el).attr("src");

        if (src) {
          try {
            const fullJsUrl = new URL(src, currentUrl).href;
            jsFiles.add(fullJsUrl);
          } catch {}
        }
      });

      $("a[href]").each((i, el) => {
        const href = $(el).attr("href");

        if (!href) return;

        try {
          const fullUrl = new URL(href, currentUrl);

          if (fullUrl.hostname === baseUrl.hostname) {
            const cleanUrl = fullUrl.origin + fullUrl.pathname;

            routes.add(fullUrl.pathname);

            if (!visited.has(cleanUrl) && !queue.includes(cleanUrl)) {
              queue.push(cleanUrl);
            }
          }
        } catch {}
      });

      $("form").each((i, form) => {
        const action = $(form).attr("action") || currentUrl;
        const method = ($(form).attr("method") || "GET").toUpperCase();

        const inputs = [];

        $(form)
          .find("input, textarea, select")
          .each((j, input) => {
            const labelText =
            $(input).closest("label").text().trim() ||
            $(input).parent().find("label").first().text().trim();

          const selectOption =
            $(input).find("option").first().text().trim();

          inputs.push({
            name:
              $(input).attr("name") ||
              $(input).attr("id") ||
              $(input).attr("placeholder") ||
              $(input).attr("aria-label") ||
              labelText ||
              selectOption ||
              "unknown-input",

            inputType:
              $(input).attr("type") ||
              input.tagName ||
              "text"
          });
          });

        forms.push({
          pageUrl: currentUrl,
          action,
          method,
          inputs
        });
      });
    } catch (error) {
      continue;
    }
  }

  let riskLevel = "Low";

  if (forms.length > 5 || jsFiles.size > 10) {
    riskLevel = "Medium";
  }

  if (forms.length > 10 || routes.size > 30) {
    riskLevel = "High";
  }

  return {
    pagesDiscovered: pages,
    routesDiscovered: Array.from(routes),
    formsDiscovered: forms,
    technologies: Array.from(technologies),
    jsFiles: Array.from(jsFiles),
    summary: {
      totalPages: pages.length,
      totalRoutes: routes.size,
      totalForms: forms.length,
      totalJsFiles: jsFiles.size,
      totalTechnologies: technologies.size
    },
    riskLevel
  };
}

async function runDynamicInputAnalysis(targetUrl) {
  const discovery = await runDynamicDiscovery(targetUrl);

  const parameters = [];
  const analyzedForms = [];

  for (const pageUrl of discovery.pagesDiscovered || []) {
    try {
      const urlObj = new URL(pageUrl);

      urlObj.searchParams.forEach((value, key) => {
        parameters.push({
          pageUrl,
          parameter: key,
          location: "URL Query",
          risk: "Medium"
        });
      });
    } catch {}
  }

  for (const form of discovery.formsDiscovered || []) {
    const analyzedInputs = [];

    for (const input of form.inputs || []) {
      let risk = "Low";

      const inputType = input.inputType || "text";
      const inputName = input.name || "unnamed";

      if (inputType === "hidden") risk = "Medium";
      if (inputType === "password") risk = "High";
      if (inputType === "file") risk = "High";

      if (
        inputName.toLowerCase().includes("token") ||
        inputName.toLowerCase().includes("csrf")
      ) {
        risk = "Medium";
      }

      analyzedInputs.push({
        name:
        inputName !== "unnamed"
          ? inputName
          : input.id || input.placeholder || input.inputType || "unnamed-field",
        inputType,
        risk
      });

      parameters.push({
        pageUrl: form.pageUrl,
        parameter: inputName,
        location: form.method || "FORM",
        risk
      });
    }

    analyzedForms.push({
      pageUrl: form.pageUrl,
      action: form.action,
      method: form.method,
      inputs: analyzedInputs
    });
  }

  const totalInputs = analyzedForms.reduce(
    (count, form) => count + form.inputs.length,
    0
  );

  const hiddenInputs = analyzedForms.reduce(
    (count, form) =>
      count + form.inputs.filter(input => input.inputType === "hidden").length,
    0
  );

  const passwordInputs = analyzedForms.reduce(
    (count, form) =>
      count + form.inputs.filter(input => input.inputType === "password").length,
    0
  );

  const fileInputs = analyzedForms.reduce(
    (count, form) =>
      count + form.inputs.filter(input => input.inputType === "file").length,
    0
  );

  let riskLevel = "Low";

  if (passwordInputs > 0 || hiddenInputs > 3) {
    riskLevel = "Medium";
  }

  if (fileInputs > 0 || parameters.length > 20) {
    riskLevel = "High";
  }

  return {
    targetUrl,
    parameters,
    forms: analyzedForms,
    jsFiles: discovery.jsFiles || [],
    summary: {
      totalParameters: parameters.length,
      totalForms: analyzedForms.length,
      totalInputs,
      hiddenInputs,
      passwordInputs,
      fileInputs,
      jsFiles: discovery.jsFiles?.length || 0
    },
    riskLevel
  };
}

async function runDynamicAuthAssessment(targetUrl) {
  const response = await axios.get(targetUrl, {
    timeout: 12000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      "User-Agent": "SecurityPlatformDynamicAuthScanner/1.0"
    }
  });

  const html = response.data || "";
  const $ = cheerio.load(html);

  const loginForms = [];
  let passwordFields = 0;
  let hiddenFields = 0;
  const authFindings = [];

  $("form").each((i, form) => {
    const inputs = [];

    $(form).find("input").each((j, input) => {
      const type = ($(input).attr("type") || "text").toLowerCase();
      const name = $(input).attr("name") || $(input).attr("id") || "unnamed";

      if (type === "password") passwordFields++;
      if (type === "hidden") hiddenFields++;

      inputs.push({
        name,
        inputType: type
      });
    });

    const hasPassword = inputs.some(input => input.inputType === "password");

    if (hasPassword) {
      loginForms.push({
        action: $(form).attr("action") || targetUrl,
        method: ($(form).attr("method") || "GET").toUpperCase(),
        inputs
      });
    }
  });

  const cookies = response.headers["set-cookie"] || [];
  const cookieSecurity = analyzeCookies(cookies);

  if (!loginForms.length) {
    authFindings.push({
      title: "No Login Form Detected",
      severity: "Info",
      description: "No password-based login form was detected on the target page.",
      recommendation: "Verify authentication manually if the login page exists elsewhere."
    });
  }

  loginForms.forEach(form => {
    if (form.method === "GET") {
      authFindings.push({
        title: "Login Form Uses GET Method",
        severity: "High",
        description: "Credentials may be exposed in URL query strings.",
        recommendation: "Use POST method for authentication forms."
      });
    }
  });

  if (passwordFields > 0 && !targetUrl.startsWith("https://")) {
    authFindings.push({
      title: "Password Field Over Non-HTTPS",
      severity: "Critical",
      description: "Password input detected on a non-HTTPS page.",
      recommendation: "Force HTTPS for all authentication pages."
    });
  }

  cookieSecurity.forEach(cookie => {
    if (!cookie.httpOnly || !cookie.secure) {
      authFindings.push({
        title: "Weak Authentication Cookie Flags",
        severity: "Medium",
        description: "One or more cookies are missing HttpOnly or Secure flags.",
        recommendation: "Set HttpOnly, Secure, and SameSite attributes on authentication cookies."
      });
    }
  });

  let riskLevel = "Low";

  if (authFindings.some(f => f.severity === "Medium")) riskLevel = "Medium";
  if (authFindings.some(f => f.severity === "High")) riskLevel = "High";
  if (authFindings.some(f => f.severity === "Critical")) riskLevel = "Critical";

  return {
    targetUrl,
    loginForms,
    passwordFields,
    hiddenFields,
    cookieSecurity,
    authFindings,
    summary: {
      loginForms: loginForms.length,
      passwordFields,
      hiddenFields,
      cookieIssues: cookieSecurity.filter(c => !c.httpOnly || !c.secure).length,
      totalFindings: authFindings.length
    },
    riskLevel
  };
}

async function runDynamicSecurityControls(targetUrl) {
  const response = await axios.get(targetUrl, {
    timeout: 12000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      "User-Agent": "SecurityPlatformControlsScanner/1.0"
    }
  });

  const headers = response.headers || {};
  const cookies = headers["set-cookie"] || [];

  const headerChecks = checkSecurityHeaders(headers);
  const cookieSecurity = analyzeCookies(cookies);

  const controlFindings = [];

  headerChecks.forEach(item => {
    if (item.status === "Missing") {
      controlFindings.push({
        title: `Missing ${item.name}`,
        severity: item.severity || "Medium",
        description: `${item.name} security header is not configured.`,
        recommendation: `Configure ${item.name} header to improve browser-side protection.`
      });
    }
  });

  const httpsEnabled = targetUrl.startsWith("https://");

  if (!httpsEnabled) {
    controlFindings.push({
      title: "HTTPS Not Enforced",
      severity: "High",
      description: "Target is using HTTP instead of HTTPS.",
      recommendation: "Redirect all HTTP traffic to HTTPS and use valid TLS certificates."
    });
  }

  const corsReview = {
    accessControlAllowOrigin:
      headers["access-control-allow-origin"] || "Not Configured",
    accessControlAllowCredentials:
      headers["access-control-allow-credentials"] || "Not Configured",
    risk: "Low"
  };

  if (
    headers["access-control-allow-origin"] === "*" &&
    headers["access-control-allow-credentials"] === "true"
  ) {
    corsReview.risk = "High";

    controlFindings.push({
      title: "Unsafe CORS Configuration",
      severity: "High",
      description: "CORS allows wildcard origin with credentials.",
      recommendation: "Avoid wildcard origins when credentials are enabled."
    });
  } else if (headers["access-control-allow-origin"] === "*") {
    corsReview.risk = "Medium";

    controlFindings.push({
      title: "Wildcard CORS Origin",
      severity: "Medium",
      description: "CORS allows requests from any origin.",
      recommendation: "Restrict allowed origins to trusted domains only."
    });
  }

  cookieSecurity.forEach(cookie => {
    if (!cookie.httpOnly || !cookie.secure || !cookie.sameSite) {
      controlFindings.push({
        title: "Weak Cookie Security Attributes",
        severity: "Medium",
        description: "Cookie is missing HttpOnly, Secure, or SameSite attribute.",
        recommendation: "Set HttpOnly, Secure, and SameSite attributes for sensitive cookies."
      });
    }
  });

  const failedControls = headerChecks.filter(h => h.status === "Missing").length;
  const passedControls = headerChecks.filter(h => h.status === "Present").length;
  const cookieIssues = cookieSecurity.filter(
    c => !c.httpOnly || !c.secure || !c.sameSite
  ).length;

  let riskLevel = "Low";

  if (controlFindings.some(f => f.severity === "Medium")) riskLevel = "Medium";
  if (controlFindings.some(f => f.severity === "High")) riskLevel = "High";
  if (controlFindings.some(f => f.severity === "Critical")) riskLevel = "Critical";

  return {
    targetUrl,
    httpsEnabled,
    statusCode: response.status,
    headers,
    headerChecks,
    cookieSecurity,
    corsReview,
    controlFindings,
    summary: {
      totalControls: headerChecks.length,
      passedControls,
      failedControls,
      cookieIssues,
      totalFindings: controlFindings.length
    },
    riskLevel
  };
}

async function runDynamicApiSecurity(targetUrl) {
  const response = await axios.get(targetUrl, {
    timeout: 12000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      "User-Agent": "SecurityPlatformApiScanner/1.0"
    }
  });

  const html = response.data || "";
  const headers = response.headers || {};
  const $ = cheerio.load(html);

  const discoveredApis = new Set();
  const swaggerEndpoints = [];
  const jsonEndpoints = [];
  const apiFindings = [];

  const apiKeywords = [
    "/api/",
    "/graphql",
    "/v1/",
    "/v2/",
    "/rest/",
    "/swagger",
    "/openapi",
    "/docs"
  ];

  $("a[href], script[src]").each((i, el) => {
    const value = $(el).attr("href") || $(el).attr("src");
    if (!value) return;

    try {
      const fullUrl = new URL(value, targetUrl).href;

      if (apiKeywords.some(keyword => fullUrl.toLowerCase().includes(keyword))) {
        discoveredApis.add(fullUrl);
      }

      if (
        fullUrl.toLowerCase().includes("swagger") ||
        fullUrl.toLowerCase().includes("openapi")
      ) {
        swaggerEndpoints.push(fullUrl);
      }
    } catch {}
  });

  const commonApiPaths = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/swagger-ui"
  ];

  for (const path of commonApiPaths) {
    try {
      const testUrl = new URL(path, targetUrl).href;

      const apiRes = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: () => true,
        headers: {
          "User-Agent": "SecurityPlatformApiScanner/1.0"
        }
      });

      const contentType = apiRes.headers["content-type"] || "";

      if (apiRes.status < 400) {
        discoveredApis.add(testUrl);

        if (contentType.includes("application/json")) {
          jsonEndpoints.push(testUrl);
        }

        if (
          testUrl.includes("swagger") ||
          testUrl.includes("openapi") ||
          JSON.stringify(apiRes.data).toLowerCase().includes("openapi")
        ) {
          swaggerEndpoints.push(testUrl);
        }
      }
    } catch {}
  }

  const corsReview = {
    accessControlAllowOrigin:
      headers["access-control-allow-origin"] || "Not Configured",
    accessControlAllowCredentials:
      headers["access-control-allow-credentials"] || "Not Configured",
    risk: "Low"
  };

  if (headers["access-control-allow-origin"] === "*") {
    corsReview.risk = "Medium";

    apiFindings.push({
      title: "Wildcard CORS Origin",
      severity: "Medium",
      description: "API or application allows requests from any origin.",
      recommendation: "Restrict CORS origins to trusted domains only."
    });
  }

  if (
    headers["access-control-allow-origin"] === "*" &&
    headers["access-control-allow-credentials"] === "true"
  ) {
    corsReview.risk = "High";

    apiFindings.push({
      title: "Unsafe CORS With Credentials",
      severity: "High",
      description: "Wildcard CORS is enabled with credentials.",
      recommendation: "Never use wildcard origin when credentials are allowed."
    });
  }

  if (swaggerEndpoints.length > 0) {
    apiFindings.push({
      title: "Public API Documentation Detected",
      severity: "Medium",
      description: "Swagger/OpenAPI documentation appears publicly accessible.",
      recommendation: "Restrict API documentation in production environments."
    });
  }

  if (jsonEndpoints.length > 0) {
    apiFindings.push({
      title: "Public JSON Endpoint Detected",
      severity: "Low",
      description: "Public JSON API endpoints were discovered.",
      recommendation: "Verify that exposed JSON data does not contain sensitive information."
    });
  }

  if (discoveredApis.size === 0) {
    apiFindings.push({
      title: "No API Endpoints Detected",
      severity: "Info",
      description: "No obvious API endpoints were discovered from passive checks.",
      recommendation: "Run deeper authenticated testing if APIs exist behind login."
    });
  }

  const methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"];

  let riskLevel = "Low";
  if (apiFindings.some(f => f.severity === "Medium")) riskLevel = "Medium";
  if (apiFindings.some(f => f.severity === "High")) riskLevel = "High";
  if (apiFindings.some(f => f.severity === "Critical")) riskLevel = "Critical";

  return {
    targetUrl,
    discoveredApis: Array.from(discoveredApis),
    swaggerEndpoints: [...new Set(swaggerEndpoints)],
    jsonEndpoints: [...new Set(jsonEndpoints)],
    corsReview,
    methods,
    apiFindings,
    summary: {
      totalApis: discoveredApis.size,
      swaggerFound: [...new Set(swaggerEndpoints)].length,
      jsonEndpoints: [...new Set(jsonEndpoints)].length,
      riskyCors: corsReview.risk === "Low" ? 0 : 1,
      totalFindings: apiFindings.length
    },
    riskLevel
  };
}

async function runDynamicVulnerabilityAssessment(targetUrl, mode = "standard") {
  const response = await axios.get(targetUrl, {
    timeout: 15000,
    maxRedirects: 5,
    validateStatus: () => true,
    headers: {
      "User-Agent": "SecurityPlatformDynamicVulnScanner/1.0"
    }
  });

  const html = response.data || "";
  const headers = response.headers || {};
  const $ = cheerio.load(html);

  const reflectedParameters = [];
  const sqlErrorIndicators = [];
  const openRedirectIndicators = [];
  const sensitiveFiles = [];
  const uploadRisks = [];
  const jsSecretIndicators = [];
  const dangerousMethods = [];
  const vulnerabilityFindings = [];

  const finalUrl = new URL(targetUrl);

  // 1. Parameter risk indicators
  const riskyParams = [
    "q", "search", "query", "id", "user", "redirect", "url",
    "next", "return", "file", "path", "page", "callback"
  ];

  riskyParams.forEach(param => {
    if (finalUrl.searchParams.has(param)) {
      reflectedParameters.push({
        parameter: param,
        value: finalUrl.searchParams.get(param),
        risk: ["redirect", "url", "next", "return"].includes(param)
          ? "Open Redirect Risk"
          : "Input Reflection Risk"
      });
    }
  });

  // 2. SQL error exposure
  const sqlErrors = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sql server",
    "postgresql",
    "sqlite error",
    "syntax error at or near",
    "unclosed quotation mark",
    "warning: mysql",
    "microsoft ole db"
  ];

  sqlErrors.forEach(pattern => {
    if (html.toLowerCase().includes(pattern)) {
      sqlErrorIndicators.push(pattern);
    }
  });

  // 3. Open redirect indicators
  $("a[href]").each((i, el) => {
    const href = $(el).attr("href") || "";

    if (
      href.includes("redirect=") ||
      href.includes("returnUrl=") ||
      href.includes("next=") ||
      href.includes("url=")
    ) {
      openRedirectIndicators.push(href);
    }
  });

  // 4. Upload risk
  $("input[type='file']").each((i, input) => {
    uploadRisks.push({
      name: $(input).attr("name") || "unnamed",
      formAction: $(input).closest("form").attr("action") || "N/A"
    });
  });

  // 5. JavaScript secret indicators
  const scripts = [];
  $("script[src]").each((i, script) => {
    const src = $(script).attr("src");
    if (src) scripts.push(new URL(src, targetUrl).href);
  });

  const secretPatterns = [
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "client_secret",
    "bearer ",
    "authorization",
    "firebase",
    "aws_access_key"
  ];

  const maxScripts =
    mode === "deep" ? 10 :
    mode === "standard" ? 5 :
    2;

  for (const scriptUrl of scripts.slice(0, maxScripts)) {
    try {
      const jsRes = await axios.get(scriptUrl, {
        timeout: 7000,
        validateStatus: () => true
      });

      const jsText = String(jsRes.data || "").toLowerCase();

      secretPatterns.forEach(pattern => {
        if (jsText.includes(pattern)) {
          jsSecretIndicators.push({
            script: scriptUrl,
            indicator: pattern
          });
        }
      });
    } catch {}
  }

  // 6. Sensitive file checks
  const sensitivePaths = [
    "/.env",
    "/backup.zip",
    "/backup.tar.gz",
    "/config.json",
    "/database.sql",
    "/phpinfo.php",
    "/debug",
    "/server-status",
    "/.git/config"
  ];

  const maxSensitiveChecks =
    mode === "deep" ? sensitivePaths.length :
    mode === "standard" ? 6 :
    3;

  for (const path of sensitivePaths.slice(0, maxSensitiveChecks)) {
    try {
      const testUrl = new URL(path, targetUrl).href;

      const fileRes = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: () => true,
        headers: {
          "User-Agent": "SecurityPlatformDynamicVulnScanner/1.0"
        }
      });

      if (fileRes.status === 200) {
        const body = String(fileRes.data || "").toLowerCase();

        if (
          body.includes("password") ||
          body.includes("database") ||
          body.includes("secret") ||
          body.includes("debug") ||
          body.includes("[core]") ||
          body.length > 20
        ) {
          sensitiveFiles.push({
            url: testUrl,
            status: fileRes.status
          });
        }
      }
    } catch {}
  }

  // 7. Dangerous HTTP methods
  try {
    const optionsRes = await axios.options(targetUrl, {
      timeout: 7000,
      validateStatus: () => true
    });

    const allow = optionsRes.headers["allow"] || "";

    ["PUT", "DELETE", "TRACE", "PATCH"].forEach(method => {
      if (allow.includes(method)) {
        dangerousMethods.push(method);
      }
    });
  } catch {}

  // Findings mapping
  if (reflectedParameters.length) {
    vulnerabilityFindings.push({
      title: "Risky Input Parameters Detected",
      severity: "Medium",
      owasp: "A03: Injection",
      evidence: `${reflectedParameters.length} risky parameters found.`,
      recommendation: "Validate, sanitize, and encode all user-controlled input."
    });
  }

  if (sqlErrorIndicators.length) {
    vulnerabilityFindings.push({
      title: "SQL Error Disclosure Detected",
      severity: "High",
      owasp: "A03: Injection",
      evidence: sqlErrorIndicators.join(", "),
      recommendation: "Disable detailed database errors and use parameterized queries."
    });
  }

  if (openRedirectIndicators.length) {
    vulnerabilityFindings.push({
      title: "Open Redirect Indicators Found",
      severity: "Medium",
      owasp: "A01: Broken Access Control",
      evidence: `${openRedirectIndicators.length} redirect-like links detected.`,
      recommendation: "Allowlist redirect destinations and avoid trusting user-supplied URLs."
    });
  }

  if (sensitiveFiles.length) {
    vulnerabilityFindings.push({
      title: "Sensitive File Exposure",
      severity: "Critical",
      owasp: "A05: Security Misconfiguration",
      evidence: `${sensitiveFiles.length} sensitive paths returned accessible responses.`,
      recommendation: "Remove sensitive files from web root and block access using server rules."
    });
  }

  if (uploadRisks.length) {
    vulnerabilityFindings.push({
      title: "File Upload Surface Detected",
      severity: "High",
      owasp: "A08: Software and Data Integrity Failures",
      evidence: `${uploadRisks.length} upload inputs detected.`,
      recommendation: "Validate file type, size, extension, content, and store uploads outside web root."
    });
  }

  if (jsSecretIndicators.length) {
    vulnerabilityFindings.push({
      title: "Possible JavaScript Secret Exposure",
      severity: "High",
      owasp: "A02: Cryptographic Failures",
      evidence: `${jsSecretIndicators.length} secret-like indicators found in JavaScript.`,
      recommendation: "Remove secrets from client-side JavaScript and rotate exposed keys."
    });
  }

  if (dangerousMethods.length) {
    vulnerabilityFindings.push({
      title: "Dangerous HTTP Methods Enabled",
      severity: "Medium",
      owasp: "A05: Security Misconfiguration",
      evidence: dangerousMethods.join(", "),
      recommendation: "Disable unnecessary HTTP methods such as PUT, DELETE, TRACE, and PATCH."
    });
  }

  let riskLevel = "Low";

  if (vulnerabilityFindings.some(f => f.severity === "Medium")) riskLevel = "Medium";
  if (vulnerabilityFindings.some(f => f.severity === "High")) riskLevel = "High";
  if (vulnerabilityFindings.some(f => f.severity === "Critical")) riskLevel = "Critical";

  return {
    targetUrl,
    mode,
    statusCode: response.status,
    reflectedParameters,
    sqlErrorIndicators,
    openRedirectIndicators,
    sensitiveFiles,
    uploadRisks,
    jsSecretIndicators,
    dangerousMethods,
    vulnerabilityFindings,
    summary: {
      reflectedParameters: reflectedParameters.length,
      sqlErrors: sqlErrorIndicators.length,
      openRedirects: openRedirectIndicators.length,
      sensitiveFiles: sensitiveFiles.length,
      uploadRisks: uploadRisks.length,
      jsSecrets: jsSecretIndicators.length,
      dangerousMethods: dangerousMethods.length,
      totalFindings: vulnerabilityFindings.length
    },
    riskLevel
  };
}



app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    res.json({ message: "User registered successfully" });

  } catch (error) {
    res.status(500).json({ message: "Registration failed" });
  }
});
app.post("/register-admin", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existing = await User.findOne({ email });

    if (existing) {
      return res.status(400).json({ message: "Admin already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword,
      role: "admin"
    });

    res.json({ message: "Admin registered successfully" });

  } catch (error) {
    console.error("Admin registration error:", error);
    res.status(500).json({ message: "Admin registration failed" });
  }
});
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      "SECRET_KEY",
      { expiresIn: "1d" }
    );

    res.json({ 
      token, 
      role: user.role,
      userId: user._id 
    });

  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});
app.post("/scan", authMiddleware, async (req, res) => {
  try {
    console.log("SCAN ROUTE HIT:", req.body);

    const targetUrl = normalizeUrl(req.body.url);
    const urlObj = new URL(targetUrl);

    // const dnsLookup = await runDnsLookupModule(targetUrl);
    // console.log("DNS Lookup Module:", dnsLookup);

    const response = await axios.get(targetUrl, {
      timeout: 20000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: {
    "User-Agent": "Mozilla/5.0 SecurityPlatformScanner/1.0"
  }
    });

    console.log("AXIOS RESPONSE RECEIVED");

    const headers = response.headers;
    const html = response.data;
    const $ = cheerio.load(html);

    let sslInfo = {
      enabled: false,
      valid: false,
      daysRemaining: null,
      validFrom: null,
      validTo: null,
      issuer: "Not checked",
      message: "Website is not using HTTPS"
    };

    if (urlObj.protocol === "https:") {
      try {
   
        console.log("SSL CHECK STARTED");

        const ssl = await sslChecker(urlObj.hostname);

        console.log("SSL CHECK FINISHED");

        sslInfo = {
          enabled: true,
          valid: ssl.valid,
          daysRemaining: ssl.daysRemaining,
          validFrom: ssl.validFrom,
          validTo: ssl.validTo,
          issuer: ssl.issuer,
          message: ssl.valid
            ? "SSL certificate is valid"
            : "SSL certificate may be invalid"
        };
      } catch (err) {
        sslInfo = {
          enabled: true,
          valid: false,
          daysRemaining: null,
          validFrom: null,
          validTo: null,
          issuer: "Unknown",
          message: "Unable to verify SSL certificate"
        };
      }
    }

    console.log("HEADER FINDINGS STARTED");
    const headerFindings = checkSecurityHeaders(headers);
    console.log("HEADER FINDINGS DONE");

    console.log("COOKIE FINDINGS STARTED");
    const cookieFindings = analyzeCookies(headers["set-cookie"]);
    console.log("COOKIE FINDINGS DONE");

    console.log("VULN DETECTION STARTED");
    const findings = detectVulnerabilities(headers, targetUrl, html);
    console.log("VULN DETECTION DONE");

    const htmlLower = html.toLowerCase();

    const technologies = {
      server: headers["server"] || "Hidden / Not detected",
      poweredBy: headers["x-powered-by"] || "Hidden / Not detected",
      frameworks: [],
      cms: [],
      languages: [],
      cdn: [],
      analytics: [],
      security: [],
      databases: [],
      allDetected: []
    };

    // Server / CDN detection
    if ((headers["server"] || "").toLowerCase().includes("nginx")) {
      technologies.allDetected.push("Nginx");
    }

    if ((headers["server"] || "").toLowerCase().includes("apache")) {
      technologies.allDetected.push("Apache");
    }

    if ((headers["server"] || "").toLowerCase().includes("iis")) {
      technologies.allDetected.push("Microsoft IIS");
    }

    if (
      (headers["server"] || "").toLowerCase().includes("cloudflare") ||
      headers["cf-ray"] ||
      headers["cf-cache-status"]
    ) {
      technologies.cdn.push("Cloudflare");
      technologies.allDetected.push("Cloudflare");
    }

    // Backend / powered by
    if ((headers["x-powered-by"] || "").toLowerCase().includes("express")) {
      technologies.frameworks.push("Express.js");
      technologies.allDetected.push("Express.js");
    }

    if ((headers["x-powered-by"] || "").toLowerCase().includes("php")) {
      technologies.languages.push("PHP");
      technologies.allDetected.push("PHP");
    }

    if ((headers["x-powered-by"] || "").toLowerCase().includes("asp.net")) {
      technologies.frameworks.push("ASP.NET");
      technologies.allDetected.push("ASP.NET");
    }

    // Frontend frameworks
    if (htmlLower.includes("react") || htmlLower.includes("__react")) {
      technologies.frameworks.push("React");
      technologies.allDetected.push("React");
    }

    if (htmlLower.includes("vue") || htmlLower.includes("__vue")) {
      technologies.frameworks.push("Vue.js");
      technologies.allDetected.push("Vue.js");
    }

    if (htmlLower.includes("angular")) {
      technologies.frameworks.push("Angular");
      technologies.allDetected.push("Angular");
    }

    if (htmlLower.includes("next_data") || htmlLower.includes("__next")) {
      technologies.frameworks.push("Next.js");
      technologies.allDetected.push("Next.js");
    }

    if (htmlLower.includes("nuxt")) {
      technologies.frameworks.push("Nuxt.js");
      technologies.allDetected.push("Nuxt.js");
    }

    // CMS detection
    if (
      htmlLower.includes("wp-content") ||
      htmlLower.includes("wp-includes") ||
      htmlLower.includes("wordpress")
    ) {
      technologies.cms.push("WordPress");
      technologies.allDetected.push("WordPress");
    }

    if (htmlLower.includes("drupal")) {
      technologies.cms.push("Drupal");
      technologies.allDetected.push("Drupal");
    }

    if (htmlLower.includes("joomla")) {
      technologies.cms.push("Joomla");
      technologies.allDetected.push("Joomla");
    }

    if (htmlLower.includes("shopify")) {
      technologies.cms.push("Shopify");
      technologies.allDetected.push("Shopify");
    }

    // JavaScript libraries
    if (htmlLower.includes("jquery")) {
      technologies.frameworks.push("jQuery");
      technologies.allDetected.push("jQuery");
    }

    if (htmlLower.includes("bootstrap")) {
      technologies.frameworks.push("Bootstrap");
      technologies.allDetected.push("Bootstrap");
    }

    if (htmlLower.includes("tailwind")) {
      technologies.frameworks.push("Tailwind CSS");
      technologies.allDetected.push("Tailwind CSS");
    }

    // Analytics
    if (htmlLower.includes("google-analytics") || htmlLower.includes("gtag(")) {
      technologies.analytics.push("Google Analytics");
      technologies.allDetected.push("Google Analytics");
    }

    if (htmlLower.includes("googletagmanager")) {
      technologies.analytics.push("Google Tag Manager");
      technologies.allDetected.push("Google Tag Manager");
    }

    // Security / CDN headers
    if (headers["strict-transport-security"]) {
      technologies.security.push("HSTS Enabled");
      technologies.allDetected.push("HSTS Enabled");
    }

    if (headers["content-security-policy"]) {
      technologies.security.push("Content Security Policy");
      technologies.allDetected.push("Content Security Policy");
    }

    // Remove duplicates
    technologies.frameworks = [...new Set(technologies.frameworks)];
    technologies.cms = [...new Set(technologies.cms)];
    technologies.languages = [...new Set(technologies.languages)];
    technologies.cdn = [...new Set(technologies.cdn)];
    technologies.analytics = [...new Set(technologies.analytics)];
    technologies.security = [...new Set(technologies.security)];
    technologies.allDetected = [...new Set(technologies.allDetected)];

    const links = [];
   
    $("a").each((i, el) => {
      const href = $(el).attr("href");
      if (href && links.length < 20) links.push(href);
    });

    const report = {
      target: targetUrl,
      scannedAt: new Date(),
      statusCode: response.status,
      pageTitle: $("title").text() || "No title found",

      //dnsLookup,

      ssl: sslInfo,
      technologies,
      headers,
      headerFindings,
      cookieFindings,
      findings,
      links,

      summary: {
        totalFindings: findings.length,
        critical: findings.filter(f => f.severity === "Critical").length,
        high: findings.filter(f => f.severity === "High").length,
        medium: findings.filter(f => f.severity === "Medium").length,
        low: findings.filter(f => f.severity === "Low").length
      }
    };

    console.log("SAVING REPORT");

    await Scan.create({
      ...report,
      userId: req.userId
    });

    console.log("REPORT SAVED");

    res.json(report);

    console.log("RESPONSE SENT");

  } catch (error) {
    console.log("SCAN ERROR:", error);

    res.status(500).json({
      message: "Scan failed",
      error: error.message
    });
  }
});
app.post("/port-scan", authMiddleware, async (req, res) => {
  try {
    const { target, mode } = req.body;

    if (!target) {
      return res.status(400).json({ message: "Target is required" });
    }

    const cleanTarget = target
      .replace("https://", "")
      .replace("http://", "")
      .replace("www.", "")
      .split("/")[0]
      .trim();

    let results = [];

    if (mode === "full") {
      const fullScanData = await runNmapFullScan(cleanTarget);

        results = fullScanData.results;

        var hostInfo = fullScanData.hostInfo;
    } else {
      for (const item of commonPorts) {
        const status = await scanPort(cleanTarget, item.port);

        if (status === "Open") {
          const cveInfo = getRealisticCveForService(
            item.service,
            "Version not detected",
            item.port
          );

          results.push({
            port: item.port,
            service: item.service,
            status,
            version: "Version not detected in quick scan",
            risk: item.risk,
            recommendation:
              "Review exposed service and restrict access if not required.",
            ...cveInfo
          });
        }
      }
    }

   const savedScan = await PortScan.create({
      userId: req.userId,
      target: cleanTarget,
      scannedAt: new Date(),
      hostInfo,
      results
    });

    res.json(savedScan);

  } catch (error) {
    console.error("Port scan error:", error);
    res.status(500).json({
      message: "Port scan failed",
      error: error.message
    });
  }
});
app.post("/dns-lookup", authMiddleware, async (req, res) => {
  try {
    const targetUrl = req.body.url;

    const dnsData = await runDnsLookupModule(targetUrl);

    const savedDns = await DNSLookup.create({
       userId: req.userId,
      inputUrl: targetUrl,
      domain: dnsData.domain,
      A: dnsData.A,
      AAAA: dnsData.AAAA,
      MX: dnsData.MX,
      NS: dnsData.NS,
      TXT: dnsData.TXT,
      lookedUpAt: new Date(),
       
    });

    res.json(savedDns);

  } catch (error) {
    res.status(500).json({
      message: "DNS Lookup failed",
      error: error.message
    });
  }
});
app.post("/whois-lookup", authMiddleware, async (req, res) => {
  try {
    let { domain } = req.body;

    if (!domain) {
      return res.status(400).json({ message: "Domain is required" });
    }

    domain = domain
      .replace("https://", "")
      .replace("http://", "")
      .replace("www.", "")
      .split("/")[0]
      .trim()
      .toLowerCase();

    const isPrivateOrLocal =
      domain === "localhost" ||
      domain === "127.0.0.1" ||
      domain.startsWith("192.168.") ||
      domain.startsWith("10.") ||
      domain.startsWith("172.16.") ||
      domain.startsWith("172.17.") ||
      domain.startsWith("172.18.") ||
      domain.startsWith("172.19.") ||
      domain.startsWith("172.20.") ||
      domain.startsWith("172.21.") ||
      domain.startsWith("172.22.") ||
      domain.startsWith("172.23.") ||
      domain.startsWith("172.24.") ||
      domain.startsWith("172.25.") ||
      domain.startsWith("172.26.") ||
      domain.startsWith("172.27.") ||
      domain.startsWith("172.28.") ||
      domain.startsWith("172.29.") ||
      domain.startsWith("172.30.") ||
      domain.startsWith("172.31.");

    if (isPrivateOrLocal) {
      let resolvedIPs = [];

      try {
        resolvedIPs = await dns.resolve4(domain);
      } catch (err) {
        resolvedIPs = [];
      }
      const savedWhois = await WhoisScan.create({
       userId: req.userId,
        domain,
        resolvedIPs: [],
        registrar: "Private/Internal Resource",
        creationDate: "Not Applicable",
        expirationDate: "Not Applicable",
        updatedDate: "Not Applicable",
        nameServers: [],
        status: "Internal Network Resource",
        country: "Local Network",
        scannedAt: new Date()
          
      });

      return res.json(savedWhois);
    }
// const resolvedIPs = await dns.resolve4(domain).catch(() => []);
    if (!domain.includes(".")) {
      const savedWhois = await WhoisScan.create({
            userId: req.userId,
        domain,
        registrar: "Invalid Domain Format",
        creationDate: "Not Applicable",
        expirationDate: "Not Applicable",
        updatedDate: "Not Applicable",
        nameServers: [],
        status: "Invalid or Unregistered Domain",
        country: "Not Applicable",
        scannedAt: new Date()
      });

      return res.json(savedWhois);
    }

    let finalData = null;

    try {
      const whoisResult = await whois(domain);
      console.log("WHOIS RAW RESULT:", whoisResult);

      const rawText = JSON.stringify(whoisResult).toLowerCase();

      const whoisBlocked =
        rawText.includes("rate limit") ||
        rawText.includes("rdap") ||
        rawText.includes("retired") ||
        rawText.includes("try again");

      if (!whoisBlocked) {
        finalData = {
          domain,
          registrar:
            whoisResult.registrar ||
            whoisResult.registrarName ||
            whoisResult.sponsoringRegistrar ||
            "Not Available",

          creationDate:
            whoisResult.creationDate ||
            whoisResult.createdDate ||
            whoisResult.created ||
            "Not Available",

          expirationDate:
            whoisResult.registryExpiryDate ||
            whoisResult.expiryDate ||
            whoisResult.expirationDate ||
            whoisResult.expires ||
            "Not Available",

          updatedDate:
            whoisResult.updatedDate ||
            whoisResult.lastUpdated ||
            "Not Available",

          nameServers:
            whoisResult.nameServer
              ? Array.isArray(whoisResult.nameServer)
                ? whoisResult.nameServer
                : [whoisResult.nameServer]
              : whoisResult.nameServers
              ? Array.isArray(whoisResult.nameServers)
                ? whoisResult.nameServers
                : [whoisResult.nameServers]
              : [],

          status:
            whoisResult.domainStatus ||
            whoisResult.status ||
            "Not Available",

          country:
            whoisResult.registrantCountry ||
            whoisResult.country ||
            "Not Available"
        };
      }
    } catch (whoisError) {
      console.log("WHOIS failed, trying RDAP...");
    }

    if (!finalData || finalData.registrar === "Not Available") {
      try {
        const rdapResponse = await axios.get(`https://rdap.org/domain/${domain}`);
        const rdap = rdapResponse.data;

        console.log("RDAP RAW RESULT:", rdap);

        const events = rdap.events || [];

        const getEventDate = (eventAction) => {
          const event = events.find(e => e.eventAction === eventAction);
          return event ? event.eventDate : "Not Available";
        };

        const registrarEntity = rdap.entities?.find(entity =>
          entity.roles?.includes("registrar")
        );

        let registrarName = "Not Available";

        if (registrarEntity?.vcardArray?.[1]) {
          const fn = registrarEntity.vcardArray[1].find(item => item[0] === "fn");
          registrarName = fn ? fn[3] : "Not Available";
        }

        finalData = {
          domain,
          registrar: registrarName,
          creationDate: getEventDate("registration"),
          expirationDate: getEventDate("expiration"),
          updatedDate: getEventDate("last changed"),
          nameServers: rdap.nameservers
            ? rdap.nameservers.map(ns => ns.ldhName)
            : [],
          status: rdap.status ? rdap.status.join(", ") : "Not Available",
          country: "RDAP Protected / Not Public"
        };

      } catch (rdapError) {
        console.error("RDAP failed:", rdapError.message);

        finalData = {
          domain,
          registrar: "WHOIS/RDAP Data Not Available",
          creationDate: "Not Available",
          expirationDate: "Not Available",
          updatedDate: "Not Available",
          nameServers: [],
          status: "Lookup Failed or Domain Not Found",
          country: "Not Available"
        };
      }
    }

    const resolvedIPs = await dns.resolve4(domain).catch(() => []);

    const savedWhois = await WhoisScan.create({
      userId: req.userId,
      ...finalData,
      resolvedIPs,
      scannedAt: new Date()
    });

    res.json(savedWhois);

  } catch (error) {
    console.error("WHOIS Lookup Error:", error);
    res.status(500).json({ message: "WHOIS lookup failed" });
  }
});
app.post("/subdomain-discovery", authMiddleware,async (req, res) => {
  try {
    let { domain } = req.body;

    if (!domain) {
      return res.status(400).json({ message: "Domain is required" });
    }

    domain = domain
      .replace("https://", "")
      .replace("http://", "")
      .replace("www.", "")
      .split("/")[0]
      .trim()
      .toLowerCase();

    if (
      domain === "localhost" ||
      domain === "127.0.0.1" ||
      !domain.includes(".")
    ) {
      const savedScan = await SubdomainScan.create({
        domain,
        subdomains: [],
        totalFound: 0,
        source: "Not applicable for localhost, IP address, or invalid domain",
        scannedAt: new Date()
      });

      return res.json(savedScan);
    }

    const response = await axios.get(
      `https://crt.sh/?q=%25.${domain}&output=json`,
      {
        timeout: 45000,
        headers: {
          "User-Agent": "SecurityPlatform/1.0"
        }
      }
    );

    const rawData = Array.isArray(response.data) ? response.data : [];

    let subdomains = rawData
      .map(item => item.name_value)
      .filter(Boolean)
      .flatMap(name => name.split("\n"))
      .map(name => name.replace("*.", "").trim().toLowerCase())
      .filter(name => name.endsWith(domain));

    subdomains = [...new Set(subdomains)];

    const savedScan = await SubdomainScan.create({
      userId: req.userId,
      domain,
      subdomains,
      totalFound: subdomains.length,
      source: "crt.sh Certificate Transparency Logs",
      scannedAt: new Date()
    });

    res.json(savedScan);

  } catch (error) {
    console.error("Subdomain discovery error:", error.message);

    const savedScan = await SubdomainScan.create({
      userId: req.userId,
      domain: req.body.domain,
      subdomains: [],
      totalFound: 0,
      source: "crt.sh timeout or unavailable / 502 error",
      scannedAt: new Date()
    });

    res.json(savedScan);
  }
});
app.post("/daa-scan", authMiddleware, async (req, res) => {
  try {
    const { url, crawlDepth } = req.body;

    if (!url) {
      return res.status(400).json({ message: "Target URL is required" });
    }

    const targetUrl = normalizeUrl(url);
    const domain = new URL(targetUrl).hostname.replace(/^www\./, "");

    const depth = Number(crawlDepth) || 10;

    const discovery = await crawlWebsite(targetUrl, depth);

    const savedScan = await DAAScan.create({
      userId: req.userId,
      target: targetUrl,
      domain,
      crawlDepth: depth,
      discovery,
      summary: {
        pagesCrawled: discovery.summary?.totalPagesCrawled || 0,
        internalLinks: discovery.summary?.internalLinks || 0,
        externalLinks: discovery.summary?.externalLinks || 0,
        formsFound: discovery.summary?.formsFound || 0,
        apiEndpoints: discovery.summary?.apiEndpoints || 0
      },
      scannedAt: new Date()
    });

    res.json(savedScan);

  } catch (error) {
    console.error("DAA scan error:", error);
    res.status(500).json({
      message: "Dynamic Application Assessment failed",
      error: error.message
    });
  }
});
app.post("/full-scan",authMiddleware, async (req, res) => {
  try {
    const input = req.body.url;

    if (!input) {
      return res.status(400).json({ message: "URL is required" });
    }

    const targetUrl = normalizeUrl(input);
    const domain = new URL(targetUrl).hostname.replace(/^www\./, "");

    // 1. Website vulnerability scan
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true
    });

    const headers = response.headers;
    const html = response.data;
    const $ = cheerio.load(html);

    let sslInfo = {
      enabled: false,
      valid: false,
      daysRemaining: null,
      validFrom: null,
      validTo: null,
      issuer: "Not checked",
      message: "Website is not using HTTPS"
    };

    if (new URL(targetUrl).protocol === "https:") {
      try {
        const ssl = await sslChecker(domain);
        sslInfo = {
          enabled: true,
          valid: ssl.valid,
          daysRemaining: ssl.daysRemaining,
          validFrom: ssl.validFrom,
          validTo: ssl.validTo,
          issuer: ssl.issuer,
          message: ssl.valid ? "SSL certificate is valid" : "SSL certificate may be invalid"
        };
      } catch {
        sslInfo.message = "Unable to verify SSL certificate";
      }
    }

    const headerFindings = checkSecurityHeaders(headers);
    const cookieFindings = analyzeCookies(headers["set-cookie"]);
    const findings = detectVulnerabilities(headers, targetUrl, html);

    const links = [];
    $("a").each((i, el) => {
      const href = $(el).attr("href");
      if (href && links.length < 20) links.push(href);
    });

    const htmlLower = html.toLowerCase();

    const technologies = {
      server: headers["server"] || "Hidden / Not detected",
      poweredBy: headers["x-powered-by"] || "Hidden / Not detected",
      frameworks: [],
      cms: [],
      languages: [],
      cdn: [],
      analytics: [],
      security: [],
      databases: [],
      allDetected: []
    };

    // Server / CDN detection
    if ((headers["server"] || "").toLowerCase().includes("nginx")) {
      technologies.allDetected.push("Nginx");
    }

    if ((headers["server"] || "").toLowerCase().includes("apache")) {
      technologies.allDetected.push("Apache");
    }

    if ((headers["server"] || "").toLowerCase().includes("iis")) {
      technologies.allDetected.push("Microsoft IIS");
    }

    if (
      (headers["server"] || "").toLowerCase().includes("cloudflare") ||
      headers["cf-ray"] ||
      headers["cf-cache-status"]
    ) {
      technologies.cdn.push("Cloudflare");
      technologies.allDetected.push("Cloudflare");
    }

    // Backend / powered by
    if ((headers["x-powered-by"] || "").toLowerCase().includes("express")) {
      technologies.frameworks.push("Express.js");
      technologies.allDetected.push("Express.js");
    }

    if ((headers["x-powered-by"] || "").toLowerCase().includes("php")) {
      technologies.languages.push("PHP");
      technologies.allDetected.push("PHP");
    }

    if ((headers["x-powered-by"] || "").toLowerCase().includes("asp.net")) {
      technologies.frameworks.push("ASP.NET");
      technologies.allDetected.push("ASP.NET");
    }

    // Frontend frameworks
    if (htmlLower.includes("react") || htmlLower.includes("__react")) {
      technologies.frameworks.push("React");
      technologies.allDetected.push("React");
    }

    if (htmlLower.includes("vue") || htmlLower.includes("__vue")) {
      technologies.frameworks.push("Vue.js");
      technologies.allDetected.push("Vue.js");
    }

    if (htmlLower.includes("angular")) {
      technologies.frameworks.push("Angular");
      technologies.allDetected.push("Angular");
    }

    if (htmlLower.includes("next_data") || htmlLower.includes("__next")) {
      technologies.frameworks.push("Next.js");
      technologies.allDetected.push("Next.js");
    }

    if (htmlLower.includes("nuxt")) {
      technologies.frameworks.push("Nuxt.js");
      technologies.allDetected.push("Nuxt.js");
    }

    // CMS detection
    if (
      htmlLower.includes("wp-content") ||
      htmlLower.includes("wp-includes") ||
      htmlLower.includes("wordpress")
    ) {
      technologies.cms.push("WordPress");
      technologies.allDetected.push("WordPress");
    }

    if (htmlLower.includes("drupal")) {
      technologies.cms.push("Drupal");
      technologies.allDetected.push("Drupal");
    }

    if (htmlLower.includes("joomla")) {
      technologies.cms.push("Joomla");
      technologies.allDetected.push("Joomla");
    }

    if (htmlLower.includes("shopify")) {
      technologies.cms.push("Shopify");
      technologies.allDetected.push("Shopify");
    }

    // JavaScript libraries
    if (htmlLower.includes("jquery")) {
      technologies.frameworks.push("jQuery");
      technologies.allDetected.push("jQuery");
    }

    if (htmlLower.includes("bootstrap")) {
      technologies.frameworks.push("Bootstrap");
      technologies.allDetected.push("Bootstrap");
    }

    if (htmlLower.includes("tailwind")) {
      technologies.frameworks.push("Tailwind CSS");
      technologies.allDetected.push("Tailwind CSS");
    }

    // Analytics
    if (htmlLower.includes("google-analytics") || htmlLower.includes("gtag(")) {
      technologies.analytics.push("Google Analytics");
      technologies.allDetected.push("Google Analytics");
    }

    if (htmlLower.includes("googletagmanager")) {
      technologies.analytics.push("Google Tag Manager");
      technologies.allDetected.push("Google Tag Manager");
    }

    // Security / CDN headers
    if (headers["strict-transport-security"]) {
      technologies.security.push("HSTS Enabled");
      technologies.allDetected.push("HSTS Enabled");
    }

    if (headers["content-security-policy"]) {
      technologies.security.push("Content Security Policy");
      technologies.allDetected.push("Content Security Policy");
    }

    // Remove duplicates
    technologies.frameworks = [...new Set(technologies.frameworks)];
    technologies.cms = [...new Set(technologies.cms)];
    technologies.languages = [...new Set(technologies.languages)];
    technologies.cdn = [...new Set(technologies.cdn)];
    technologies.analytics = [...new Set(technologies.analytics)];
    technologies.security = [...new Set(technologies.security)];
    technologies.allDetected = [...new Set(technologies.allDetected)];

    // 2. DNS Lookup
    const dnsLookup = await runDnsLookupModule(targetUrl);

    // 3. Port Scan + CVE
    const portResults = [];

    for (const item of commonPorts) {
      const status = await scanPort(domain, item.port);
      const cveInfo = getRealisticCveForService(item.service, item.port, status);

      portResults.push({
        port: item.port,
        service: item.service,
        status,
        risk: status === "Open" ? item.risk : "None",
        recommendation:
          status === "Open"
            ? "Review exposed service and restrict access if not required."
            : "No action required.",
        ...cveInfo
      });
    }

    // 5. Subdomain basic placeholder
    let subdomainData = {
      domain,
      subdomains: [],
      totalFound: 0,
      source: "Use detailed subdomain module for full CT log results"
    };
    // 4. WHOIS basic reuse
    let whoisData = {
      domain,
      registrar: "Run separate WHOIS for detailed data",
      creationDate: "Not Available",
      expirationDate: "Not Available",
      nameServers: [],
      status: "Included in full scan summary"
    };

    // Risk Score Calculation
    let riskScore = 100;

    const criticalFindings =
      findings.filter(f => f.severity === "Critical").length;

    const highFindings =
      findings.filter(f => f.severity === "High").length;

    const mediumFindings =
      findings.filter(f => f.severity === "Medium").length;

    const openPorts =
      portResults.filter(p => p.status === "Open").length;

    const criticalCves =
      portResults.filter(p => p.cveSeverity === "Critical").length;

    const highCves =
      portResults.filter(p => p.cveSeverity === "High").length;

    // Website vulnerabilities
    riskScore -= criticalFindings * 20;
    riskScore -= highFindings * 10;
    riskScore -= mediumFindings * 5;

    // Open services
    riskScore -= openPorts * 2;

    // CVEs
    riskScore -= criticalCves * 15;
    riskScore -= highCves * 8;

    // Large attack surface
    if (subdomainData.totalFound > 10) {
      riskScore -= 10;
    }

    riskScore = Math.max(0, riskScore);

    let riskLevel = "Low";

    if (riskScore < 40) {
      riskLevel = "Critical";
    } else if (riskScore < 65) {
      riskLevel = "High";
    } else if (riskScore < 85) {
      riskLevel = "Medium";
    }

    
    

    const fullReport = {
      userId: req.userId,
      reportType: "Full Security Scan",
      target: targetUrl,
      domain,
      scannedAt: new Date(),
      riskScore,
      riskLevel,

      website: {
        statusCode: response.status,
        pageTitle: $("title").text() || "No title found",
        ssl: sslInfo,
        technologies,
        headers,
        headerFindings,
        cookieFindings,
        findings,
        links,
        
        summary: {
          totalFindings: findings.length,
          critical: findings.filter(f => f.severity === "Critical").length,
          high: findings.filter(f => f.severity === "High").length,
          medium: findings.filter(f => f.severity === "Medium").length,
          low: findings.filter(f => f.severity === "Low").length
        }
      },

      dns: dnsLookup,

      ports: {
        target: domain,
        results: portResults,
        openPorts: portResults.filter(p => p.status === "Open").length,
        criticalCves: portResults.filter(p => p.cveSeverity === "Critical").length,
        highCves: portResults.filter(p => p.cveSeverity === "High").length
      },

      whois: whoisData,
      subdomains: subdomainData
    };

    const savedFullScan = await FullScan.create(fullReport);
    res.json(savedFullScan);

  } catch (error) {
    console.error("Full scan error:", error);
    res.status(500).json({
      message: "Full scan failed",
      error: error.message
    });
  }
});
app.post("/dynamic-discovery-scan", authMiddleware, async (req, res) => {
  try {
    console.log("BODY:", req.body);

    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    console.log("FINAL URL:", finalUrl);

    const result = await runDynamicDiscovery(finalUrl);

    console.log("DISCOVERY RESULT:", result);

    const savedScan = await DynamicDiscoveryScan.create({
      userId: req.userId,
      targetUrl: finalUrl,
      ...result
    });

    console.log("SCAN SAVED");

    res.json(savedScan);

  } catch (error) {

    console.log("DYNAMIC ERROR:", error);

    res.status(500).json({
      message: "Dynamic discovery scan failed",
      error: error.message
    });
  }
});
app.post("/dynamic-input-analysis", authMiddleware, async (req, res) => {
  try {
    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    const result = await runDynamicInputAnalysis(finalUrl);

    const savedAnalysis = await DynamicInputAnalysis.create({
      userId: req.userId,
      ...result
    });

    res.json(savedAnalysis);

  } catch (error) {
    console.error("Input analysis error:", error);

    res.status(500).json({
      message: "Dynamic input analysis failed",
      error: error.message
    });
  }
});
app.post("/dynamic-auth-assessment", authMiddleware, async (req, res) => {
  try {
    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    const result = await runDynamicAuthAssessment(finalUrl);

    const savedAuthScan = await DynamicAuthAssessment.create({
      userId: req.userId,
      ...result
    });

    res.json(savedAuthScan);

  } catch (error) {
    console.error("Authentication assessment error:", error);

    res.status(500).json({
      message: "Authentication assessment failed",
      error: error.message
    });
  }
});
app.post("/dynamic-security-controls", authMiddleware, async (req, res) => {
  try {
    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    const result = await runDynamicSecurityControls(finalUrl);

    const savedControls = await DynamicSecurityControls.create({
      userId: req.userId,
      ...result
    });

    res.json(savedControls);

  } catch (error) {
    console.error("Security controls assessment error:", error);

    res.status(500).json({
      message: "Security controls assessment failed",
      error: error.message
    });
  }
});
app.post("/dynamic-api-security", authMiddleware, async (req, res) => {
  try {
    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    const result = await runDynamicApiSecurity(finalUrl);

    const savedApiScan = await DynamicApiSecurity.create({
      userId: req.userId,
      ...result
    });

    res.json(savedApiScan);

  } catch (error) {
    console.error("API security assessment error:", error);

    res.status(500).json({
      message: "API security assessment failed",
      error: error.message
    });
  }
});
app.post("/dynamic-vulnerability-assessment", authMiddleware, async (req, res) => {
  try {
    const { targetUrl, mode } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        message: "Target URL is required"
      });
    }

    const finalUrl = targetUrl.startsWith("http")
      ? targetUrl
      : "https://" + targetUrl;

    const result = await runDynamicVulnerabilityAssessment(
      finalUrl,
      mode || "standard"
    );

    const savedVulnScan = await DynamicVulnerabilityAssessment.create({
      userId: req.userId,
      ...result
    });

    res.json(savedVulnScan);

  } catch (error) {
    console.error("Dynamic vulnerability assessment error:", error);

    res.status(500).json({
      message: "Dynamic vulnerability assessment failed",
      error: error.message
    });
  }
});




app.get("/scans", authMiddleware, async (req, res) => {

  let scans;

  if (req.userRole === "admin") {
    // 🔥 Admin → get all data
    scans = await Scan.find().sort({ scannedAt: -1 });
  } else {
    // 👤 User → only their data
    scans = await Scan.find({ userId: req.userId }).sort({ scannedAt: -1 });
  }

  res.json(scans);
});
app.get("/dns-history", authMiddleware, async (req, res) => {

  const data = req.userRole === "admin"
    ? await DNSLookup.find().sort({ lookedUpAt: -1 })
    : await DNSLookup.find({ userId: req.userId }).sort({ lookedUpAt: -1 });

  res.json(data);
});
app.get("/port-scans", authMiddleware, async (req, res) => {
   const data = req.userRole === "admin"
    ? await PortScan.find().sort({ scannedAt: -1 })
    : await PortScan.find({ userId: req.userId }).sort({ scannedAt: -1 });

  res.json(data);
});
app.get("/whois-history", authMiddleware, async (req, res) => {
  
   const data = req.userRole === "admin"
    ? await WhoisScan.find().sort({ scannedAt: -1 })
    : await WhoisScan.find({ userId: req.userId }).sort({ scannedAt: -1 });

  res.json(data);
});
app.get("/subdomain-history", authMiddleware, async (req, res) => {
  
  const data = req.userRole === "admin"
    ? await SubdomainScan.find().sort({ scannedAt: -1 })
    : await SubdomainScan.find({ userId: req.userId }).sort({ scannedAt: -1 });

  res.json(data);

});
app.get("/full-scans", authMiddleware, async (req, res) => {
  
  const data = req.userRole === "admin"
    ? await FullScan.find().sort({ scannedAt: -1 })
    : await FullScan.find({ userId: req.userId }).sort({ scannedAt: -1 });

  res.json(data);
});
app.get("/admin/all-scans", authMiddleware, adminMiddleware, async (req, res) => {
  const scans = await Scan.find().sort({ scannedAt: -1 });
  res.json(scans);
});
app.get("/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find().select("_id name email role").sort({ name: 1 });
  res.json(users);
});
app.get("/daa-scans", authMiddleware, async (req, res) => {
  try {
    const data = req.userRole === "admin"
      ? await DAAScan.find().sort({ scannedAt: -1 })
      : await DAAScan.find({ userId: req.userId }).sort({ scannedAt: -1 });

    res.json(data);
  } catch (error) {
    res.status(500).json({ message: "Failed to load DAA history" });
  }
});
app.get("/dynamic-input-analysis-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicInputAnalysis.find().sort({ scannedAt: -1 })
        : await DynamicInputAnalysis.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);

  } catch (error) {
    res.status(500).json({
      message: "Failed to load input analysis history"
    });
  }
});
app.get("/dynamic-auth-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicAuthAssessment.find().sort({ scannedAt: -1 })
        : await DynamicAuthAssessment.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);

  } catch (error) {
    res.status(500).json({
      message: "Failed to load authentication assessment history"
    });
  }
});
app.get("/dynamic-security-controls-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicSecurityControls.find().sort({ scannedAt: -1 })
        : await DynamicSecurityControls.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);

  } catch (error) {
    res.status(500).json({
      message: "Failed to load security controls history"
    });
  }
});
app.get("/dynamic-api-security-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicApiSecurity.find().sort({ scannedAt: -1 })
        : await DynamicApiSecurity.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);

  } catch (error) {
    res.status(500).json({
      message: "Failed to load API security history"
    });
  }
});
app.get("/dynamic-vulnerability-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicVulnerabilityAssessment.find().sort({ scannedAt: -1 })
        : await DynamicVulnerabilityAssessment.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);

  } catch (error) {
    res.status(500).json({
      message: "Failed to load dynamic vulnerability history"
    });
  }
});



app.get("/export-pdf", async (req, res) => {
  try {
    const scans = await Scan.find().sort({ scannedAt: -1 }).limit(1);

    if (!scans.length) {
      return res.status(404).send("No scan reports found");
    }

    const report = scans[0];

    const doc = new PDFDocument({
      size: "A4",
      margin: 45
    });

    res.setHeader("Content-Disposition", "attachment; filename=security-report.pdf");
    res.setHeader("Content-Type", "application/pdf");

    doc.pipe(res);

    // ---------- HEADER ----------
    doc
      .fontSize(24)
      .font("Helvetica-Bold")
      .fillColor("#111")
      .text("Website Vulnerability Scan Report");

    doc
      .moveDown(0.3)
      .fontSize(11)
      .font("Helvetica")
      .fillColor("#555")
      .text(`${report.target || "Target Website"} · Prepared ${new Date().toLocaleDateString()}`);

    doc.moveDown(1.5);

    // ---------- SUMMARY COUNTS ----------
    const summary = report.summary || {};

    const critical = summary.critical || 0;
    const high = summary.high || 0;
    const medium = summary.medium || 0;
    const low = summary.low || 0;
    const total = summary.totalFindings || report.findings?.length || 0;

    const startX = 45;
    const boxY = doc.y;
    const boxW = 120;
    const gap = 15;

    function summaryBox(x, number, label) {
      doc
        .fillColor("#111")
        .font("Helvetica-Bold")
        .fontSize(28)
        .text(number, x, boxY);

      doc
        .fontSize(10)
        .fillColor("#111")
        .text(label, x, boxY + 35, { width: boxW });
    }

    summaryBox(startX, critical + high, "Critical Issues");
    summaryBox(startX + boxW + gap, medium, "Moderate Issues");
    summaryBox(startX + (boxW + gap) * 2, low, "Opportunities");
    summaryBox(startX + (boxW + gap) * 3, total === 0 ? 1 : 0, "Passing Checks");

    doc.y = boxY + 70;

    // ---------- TARGET DETAILS ----------
    sectionTitle("• Target Details");

    doc
      .font("Helvetica")
      .fontSize(11)
      .fillColor("#111")
      .text(`Target URL: ${report.target || "N/A"}`)
      .text(`Status Code: ${report.statusCode || "N/A"}`)
      .text(`Page Title: ${report.pageTitle || "N/A"}`)
      .text(`Scanned At: ${report.scannedAt ? new Date(report.scannedAt).toLocaleString() : "N/A"}`);

    doc.moveDown();

    // ---------- CRITICAL / HIGH ----------
    sectionTitle("• Critical Issues");
    const findings = report.findings || [];
    const criticalFindings = findings.filter(f =>
      ["critical", "high"].includes(String(f.severity).toLowerCase())
    );

    if (criticalFindings.length) {
      criticalFindings.forEach((item, index) => {
        issueBlock(index + 1, item, "CRITICAL");
      });
    } else {
      doc.fontSize(11).font("Helvetica").text("No critical issues found.");
    }

    // ---------- MODERATE ----------
    sectionTitle("• Moderate Issues");

    const moderateFindings = findings.filter(f =>
      String(f.severity).toLowerCase() === "medium"
    );

    if (moderateFindings.length) {
      moderateFindings.forEach((item, index) => {
        issueBlock(index + 1, item, "MODERATE");
      });
    } else {
      doc.fontSize(11).font("Helvetica").text("No moderate issues found.");
    }

    // ---------- LOW / OPPORTUNITIES ----------
    sectionTitle("• Opportunities");

    const lowFindings = findings.filter(f =>
      String(f.severity).toLowerCase() === "low"
    );

    if (lowFindings.length) {
      lowFindings.forEach((item, index) => {
        issueBlock(index + 1, item, "OPPORTUNITY");
      });
    } else {
      doc.fontSize(11).font("Helvetica").text("No low-risk improvement opportunities found.");
    }

    // ---------- PASSING ----------
    sectionTitle("• What's Working");

    doc
      .fontSize(11)
      .font("Helvetica")
      .fillColor("#111")
      .text("HTTPS and basic accessibility checks should be manually verified.")
      .text("No additional passing checks were detected automatically in this scan.");

    doc.moveDown();

    // ---------- DNS LOOKUP MODULE ----------
    

    // ---------- ACTION PLAN ----------
    sectionTitle("• Priority Action Plan");

    tableHeader();

    findings.slice(0, 8).forEach((item) => {
      const severity = String(item.severity || "Medium").toLowerCase();

      let priority = "Medium";
      let effort = "Medium";
      let impact = "Medium";

      if (severity === "critical" || severity === "high") {
        priority = "High";
        effort = "Low";
        impact = "High";
      } else if (severity === "low") {
        priority = "Low";
        effort = "Low";
        impact = "Medium";
      }

      tableRow(
        priority,
        item.title || item.name || "Security Finding",
        effort,
        impact
      );
    });

    if (!findings.length) {
      tableRow("Low", "Continue regular vulnerability scanning", "Low", "Medium");
    }

    // ---------- FOOTER ----------
    doc.moveDown(2);
    doc
      .fontSize(9)
      .fillColor("#555")
      .text(
        "This vulnerability scan report was generated based on automated checks. Manual verification is recommended for complete security coverage.",
        45,
        doc.page.height - 70,
        { width: 500, align: "center" }
      );

    doc.end();

    // ---------- HELPER FUNCTIONS ----------
    function sectionTitle(title) {
      checkPageSpace(60);

      doc.moveDown(1);

      doc
        .font("Helvetica-Bold")
        .fontSize(14)
        .fillColor("#111")
        .text(title, 45, doc.y);

      doc.moveDown(0.6);
    }

    function issueBlock(number, item, badge) {
      checkPageSpace(120);

      const startY = doc.y;
      const title = item.title || item.name || "Security Finding";
      const risk = item.risk || item.status || item.description || "Security issue detected.";
      const solution = item.solution || item.value || "Review and fix this issue.";

      // Number
      doc
        .font("Helvetica-Bold")
        .fontSize(18)
        .fillColor("#111")
        .text(number, 45, startY, { width: 25 });

      // Title
      doc
        .font("Helvetica-Bold")
        .fontSize(12)
        .fillColor("#111")
        .text(title, 80, startY, { width: 340 });

      let currentY = doc.y + 6;

      // Risk
      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#333")
        .text(risk, 80, currentY, { width: 340 });

      currentY = doc.y + 6;

      // Recommendation
      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#333")
        .text(`Recommended: ${solution}`, 80, currentY, { width: 340 });

      // Badge
      doc
        .font("Helvetica-Bold")
        .fontSize(9)
        .fillColor("#111")
        .text(badge, 455, startY, { width: 90, align: "center" });

      // IMPORTANT: manually move below the whole block
      doc.y = Math.max(doc.y, startY + 75);

      doc.moveDown(0.8);
    }

    function tableHeader() {
      checkPageSpace(70);

      const y = doc.y;

      doc.font("Helvetica-Bold").fontSize(10).fillColor("#111");

      doc.text("Priority", 45, y, { width: 80 });
      doc.text("Action", 130, y, { width: 250 });
      doc.text("Effort", 390, y, { width: 70 });
      doc.text("Impact", 470, y, { width: 70 });

      doc.moveTo(45, y + 22).lineTo(540, y + 22).stroke();

      doc.y = y + 32;
    }

    function tableRow(priority, action, effort, impact) {
      checkPageSpace(40);

      const y = doc.y;

      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#111")
        .text(priority, 45, y, { width: 80 })
        .text(action, 130, y, { width: 250 })
        .text(effort, 390, y, { width: 70 })
        .text(impact, 470, y, { width: 70 });

      doc.moveDown(1);
    }

    function checkPageSpace(spaceNeeded) {
      if (doc.y + spaceNeeded > doc.page.height - 90) {
        doc.addPage();
      }
    }

  } catch (error) {
    console.log(error);
    res.status(500).send("PDF Export Failed");
  }
});
app.get("/export-dns-pdf", async (req, res) => {
  try {
    const dnsReports = await DNSLookup.find().sort({ lookedUpAt: -1 }).limit(1);

    if (!dnsReports.length) {
      return res.status(404).send("No DNS lookup reports found");
    }

    const dns = dnsReports[0];

    const doc = new PDFDocument({
      size: "A4",
      margin: 45
    });

    res.setHeader("Content-Disposition", "attachment; filename=dns-lookup-report.pdf");
    res.setHeader("Content-Type", "application/pdf");

    doc.pipe(res);

    doc
      .fontSize(24)
      .font("Helvetica-Bold")
      .fillColor("#111")
      .text("DNS Lookup Report");

    doc
      .moveDown(0.3)
      .fontSize(11)
      .font("Helvetica")
      .fillColor("#555")
      .text(`${dns.domain || "Domain"} · Prepared ${new Date().toLocaleDateString()}`);

    doc.moveDown(1.5);

    doc
      .fontSize(16)
      .font("Helvetica-Bold")
      .fillColor("#111")
      .text("DNS Lookup Results");

    doc.moveDown();

    doc
      .fontSize(12)
      .font("Helvetica")
      .text(`Domain: ${dns.domain || "Not Available"}`)
      .text(`Input URL: ${dns.inputUrl || "Not Available"}`)
      .text(`Looked Up At: ${dns.lookedUpAt ? new Date(dns.lookedUpAt).toLocaleString() : "N/A"}`);

    doc.moveDown();

    doc
      .fontSize(14)
      .font("Helvetica-Bold")
      .text("DNS Records");

    doc.moveDown(0.5);

    doc
      .fontSize(11)
      .font("Helvetica")
      .text(`A Records: ${dns.A?.length ? dns.A.join(", ") : "Not Found"}`, { width: 500 })
      .moveDown(0.4)
      .text(`AAAA Records: ${dns.AAAA?.length ? dns.AAAA.join(", ") : "Not Found"}`, { width: 500 })
      .moveDown(0.4)
      .text(`MX Records: ${
        dns.MX?.length
          ? dns.MX.map(mx => `${mx.exchange} Priority: ${mx.priority}`).join(", ")
          : "Not Found"
      }`, { width: 500 })
      .moveDown(0.4)
      .text(`NS Records: ${dns.NS?.length ? dns.NS.join(", ") : "Not Found"}`, { width: 500 })
      .moveDown(0.4)
      .text(`TXT Records: ${
        dns.TXT?.length
          ? dns.TXT.map(txt => txt.join(" ")).join(", ")
          : "Not Found"
      }`, { width: 500 });

    doc.moveDown(2);

    doc
      .fontSize(9)
      .fillColor("#555")
      .text(
        "This DNS lookup report was generated from DNS records collected for the provided domain.",
        45,
        doc.page.height - 70,
        { width: 500, align: "center" }
      );

    doc.end();

  } catch (error) {
    console.log(error);
    res.status(500).send("DNS PDF Export Failed");
  }
});
app.get("/export-port-pdf", async (req, res) => {
  try {
    const latestScan = await PortScan.findOne().sort({ scannedAt: -1 });

    if (!latestScan) {
      return res.status(404).send("No port scan report found");
    }

    const doc = new PDFDocument({ margin: 40 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=port-scan-report.pdf");

    doc.pipe(res);

    doc.fontSize(22).text("Port Scan + CVE Intelligence Report", { align: "center" });
    doc.moveDown();

    doc.fontSize(12).text(`Target: ${latestScan.target}`);
    doc.text(`Scanned At: ${new Date(latestScan.scannedAt).toLocaleString()}`);
    doc.moveDown();

    doc.fontSize(16).text("Port Scan Results");
    doc.moveDown();

    latestScan.results.forEach(item => {
      doc.fontSize(11).text(`Port: ${item.port}`);
      doc.text(`Service: ${item.service}`);
      doc.text(`Status: ${item.status}`);
      doc.text(`Risk: ${item.risk}`);

      doc.text(`CVE ID: ${item.cveId || "N/A"}`);
      doc.text(`CVE Severity: ${item.cveSeverity || "None"}`);
      doc.text(`CVSS Score: ${item.cvssScore || "N/A"}`);
      doc.text(`CVE Description: ${item.cveDescription || "No CVE description available."}`);

      doc.text(
        `Recommendation: ${
          item.cveRecommendation ||
          item.recommendation ||
          "Review exposed service and apply firewall restrictions if needed."
        }`
      );

      doc.moveDown();
    });

    doc.moveDown();
    doc.fontSize(16).text("Security Recommendation");
    doc.fontSize(11).text(
      "Close unused open ports, restrict administrative services, allow access only from trusted IP addresses, and regularly review firewall rules."
    );

    doc.end();

  } catch (error) {
    console.error(error);
    res.status(500).send("Failed to generate port scan PDF");
  }
});
app.get("/export-whois-pdf", async (req, res) => {
  try {
    const latestWhois = await WhoisScan.findOne().sort({ scannedAt: -1 });

    if (!latestWhois) {
      return res.status(404).send("No WHOIS report found");
    }

    const doc = new PDFDocument({ margin: 40 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=whois-report.pdf"
    );

    doc.pipe(res);

    doc.fontSize(22).text("WHOIS Intelligence Report", {
      align: "center"
    });

    doc.moveDown();

    doc.fontSize(12).text(`Domain: ${latestWhois.domain || "Not Available"}`);
    doc.text(`Registrar: ${latestWhois.registrar || "Not Available"}`);
    doc.text(`Creation Date: ${latestWhois.creationDate || "Not Available"}`);
    doc.text(`Expiration Date: ${latestWhois.expirationDate || "Not Available"}`);
    doc.text(`Updated Date: ${latestWhois.updatedDate || "Not Available"}`);
    doc.text(`Status: ${latestWhois.status || "Not Available"}`);
    doc.text(`Country: ${latestWhois.country || "Not Available"}`);

    doc.moveDown();

    doc.fontSize(14).text("Name Servers");

    if (latestWhois.nameServers?.length) {
      latestWhois.nameServers.forEach(ns => {
        doc.fontSize(11).text(`• ${ns}`);
      });
    } else {
      doc.fontSize(11).text("No Name Servers Found");
    }

    doc.moveDown();

    doc.fontSize(14).text("Security Recommendation");

    doc.fontSize(11).text(
      "Monitor domain expiration regularly, verify trusted registrar ownership, ensure secure name server configuration, and review domain status changes to reduce hijacking risks."
    );

    doc.end();

  } catch (error) {
    console.error("WHOIS PDF Export Error:", error);
    res.status(500).send("Failed to generate WHOIS PDF");
  }
});
app.get("/export-subdomain-pdf", async (req, res) => {
  try {
    const latestScan = await SubdomainScan.findOne().sort({ scannedAt: -1 });

    if (!latestScan) {
      return res.status(404).send("No subdomain report found");
    }

    const doc = new PDFDocument({ margin: 40 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=subdomain-report.pdf"
    );

    doc.pipe(res);

    doc.fontSize(22).text("Subdomain Discovery Report", {
      align: "center"
    });

    doc.moveDown();

    doc.fontSize(12).text(`Domain: ${latestScan.domain || "Not Available"}`);
    doc.text(`Total Subdomains Found: ${latestScan.totalFound || 0}`);
    doc.text(`Source: ${latestScan.source || "Not Available"}`);
    doc.text(
      `Scanned At: ${
        latestScan.scannedAt
          ? new Date(latestScan.scannedAt).toLocaleString()
          : "N/A"
      }`
    );

    doc.moveDown();

    doc.fontSize(14).text("Discovered Subdomains");
    doc.moveDown();

    if (latestScan.subdomains?.length) {
      latestScan.subdomains.forEach((sub, index) => {
        doc.fontSize(11).text(`${index + 1}. ${sub}`);
      });
    } else {
      doc.fontSize(11).text("No subdomains found.");
    }

    doc.moveDown();

    doc.fontSize(14).text("Security Recommendation");

    doc.fontSize(11).text(
      "Review all discovered subdomains, remove unused assets, enforce HTTPS, monitor exposed services, and include active subdomains in regular vulnerability assessments."
    );

    doc.end();

  } catch (error) {
    console.error("Subdomain PDF Export Error:", error);
    res.status(500).send("Failed to generate subdomain PDF");
  }
});
app.get("/export-full-scan-pdf", async (req, res) => {
  try {
    const scan = await FullScan.findOne().sort({ scannedAt: -1 });

    if (!scan) {
      return res.status(404).send("No full scan report found");
    }

    const doc = new PDFDocument({ margin: 45, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=full-security-assessment-report.pdf"
    );

    doc.pipe(res);

    const addSection = (title) => {
      doc.moveDown(1);
      doc.fontSize(16).fillColor("#1f4e79").text(title, { underline: true });
      doc.moveDown(0.5);
      doc.fillColor("black");
    };

    const addLine = (label, value) => {
      doc.fontSize(10).fillColor("black").text(`${label}: `, { continued: true });
      doc.fontSize(10).fillColor("#333333").text(value || "N/A");
    };

    const website = scan.website || {};
    const dns = scan.dns || {};
    const ports = scan.ports || {};
    const whois = scan.whois || {};
    const subdomains = scan.subdomains || {};

    const critical = website.summary?.critical || 0;
    const high = website.summary?.high || 0;
    const medium = website.summary?.medium || 0;
    const low = website.summary?.low || 0;
    const total = website.summary?.totalFindings || 0;

    const riskLevel =
      critical > 0 ? "Critical" :
      high > 0 ? "High" :
      medium > 0 ? "Medium" :
      total > 0 ? "Low" : "Secure";

    // Cover
    doc.rect(0, 0, doc.page.width, 95).fill("#0f172a");
    doc.fillColor("white").fontSize(24).text("Full Security Assessment Report", 45, 30);
    doc.fontSize(11).text("Website Vulnerability | DNS | Port + CVE | WHOIS | Subdomains", 45, 62);

    doc.moveDown(4);
    doc.fillColor("black");

    addSection("Report Overview");
    addLine("Target", scan.target);
    addLine("Domain", scan.domain);
    addLine("Scanned At", new Date(scan.scannedAt).toLocaleString());
    addLine("Overall Risk", riskLevel);

    addSection("Executive Summary");
    doc.fontSize(10).text(
      "This report provides a consolidated security assessment of the target asset. It includes web application security checks, SSL/TLS review, security header analysis, cookie security review, DNS intelligence, exposed port discovery, CVE mapping, WHOIS information, and subdomain discovery."
    );

    addSection("Risk Summary");
    addLine("Total Website Findings", total);
    addLine("Critical Findings", critical);
    addLine("High Findings", high);
    addLine("Medium Findings", medium);
    addLine("Low Findings", low);
    addLine("Open Ports", ports.openPorts || 0);
    addLine("Critical CVEs", ports.criticalCves || 0);
    addLine("High CVEs", ports.highCves || 0);
    addLine("Subdomains Found", subdomains.totalFound || 0);

    addSection("Target Information");
    addLine("Status Code", website.statusCode);
    addLine("Page Title", website.pageTitle);
    addLine("SSL Enabled", website.ssl?.enabled ? "Yes" : "No");
    addLine("SSL Valid", website.ssl?.valid ? "Yes" : "No");
    addLine("SSL Days Remaining", website.ssl?.daysRemaining);
    addLine("SSL Issuer", website.ssl?.issuer);
    addLine("Server", website.technologies?.server);
    addLine("Powered By", website.technologies?.poweredBy);

    addSection("Website Vulnerability Findings");

    if (website.findings?.length) {
      website.findings.forEach((f, i) => {
        doc.fontSize(11).fillColor("#111827").text(`${i + 1}. ${f.title || "Finding"}`);
        doc.fontSize(9).fillColor("black").text(`Severity: ${f.severity || "N/A"}`);
        doc.text(`Risk: ${f.risk || "N/A"}`);
        doc.text(`Solution: ${f.solution || "N/A"}`);
        doc.moveDown(0.5);
      });
    } else {
      doc.fontSize(10).text("No website vulnerability findings available.");
    }

    addSection("Security Headers Analysis");

    if (website.headerFindings?.length) {
      website.headerFindings.forEach((h, i) => {
        doc.fontSize(9).text(
          `${i + 1}. ${h.name || "Header"} | Status: ${h.status || "N/A"} | Severity: ${h.severity || "N/A"}`
        );
      });
    } else {
      doc.fontSize(10).text("No security header findings available.");
    }

    addSection("Cookie Security Review");

    if (website.cookieFindings?.length) {
      website.cookieFindings.forEach((c, i) => {
        doc.fontSize(8).text(
          `${i + 1}. ${c.cookie || "Cookie"} | Secure: ${c.secure ? "Yes" : "No"} | HttpOnly: ${c.httpOnly ? "Yes" : "No"} | SameSite: ${c.sameSite ? "Yes" : "No"} | Risk: ${c.risk || "N/A"}`
        );
      });
    } else {
      doc.fontSize(10).text("No cookie data available.");
    }

    doc.addPage();

    addSection("DNS Intelligence");
    addLine("Domain", dns.domain || scan.domain);
    addLine("A Records", dns.A?.join(", "));
    addLine("AAAA Records", dns.AAAA?.join(", "));
    addLine("MX Records", dns.MX?.map(mx => `${mx.exchange} (${mx.priority})`).join(", "));
    addLine("NS Records", dns.NS?.join(", "));
    addLine("TXT Records", dns.TXT?.map(txt => txt.join(" ")).join(" | "));

    addSection("Port Scan + CVE Mapping");

    if (ports.results?.length) {
      ports.results.forEach((p, i) => {
        doc.fontSize(9).text(
          `${i + 1}. Port ${p.port} | ${p.service} | ${p.status} | Risk: ${p.risk} | CVE: ${p.cveId} | Severity: ${p.cveSeverity} | CVSS: ${p.cvssScore}`
        );
        doc.fontSize(8).text(`Recommendation: ${p.cveRecommendation || p.recommendation || "N/A"}`);
        doc.moveDown(0.3);
      });
    } else {
      doc.fontSize(10).text("No port scan data available.");
    }

    addSection("WHOIS Details");
    addLine("Domain", whois.domain || scan.domain);
    addLine("Registrar", whois.registrar);
    addLine("Creation Date", whois.creationDate);
    addLine("Expiration Date", whois.expirationDate);
    addLine("Updated Date", whois.updatedDate);
    addLine("Name Servers", whois.nameServers?.join(", "));
    addLine("Status", whois.status);
    addLine("Country", whois.country);

    addSection("Subdomain Discovery");
    addLine("Total Found", subdomains.totalFound || 0);
    addLine("Source", subdomains.source);

    if (subdomains.subdomains?.length) {
      subdomains.subdomains.slice(0, 40).forEach((sub, i) => {
        doc.fontSize(8).text(`${i + 1}. ${sub}`);
      });
    } else {
      doc.fontSize(10).text("No subdomains found.");
    }

    addSection("Final Remediation Plan");
    doc.fontSize(10).text("1. Fix Critical and High severity findings first.");
    doc.text("2. Configure missing security headers such as CSP, HSTS, X-Frame-Options, and Referrer-Policy.");
    doc.text("3. Enforce Secure, HttpOnly, and SameSite cookie attributes.");
    doc.text("4. Close unnecessary open ports and restrict exposed services.");
    doc.text("5. Patch services mapped to CVE references.");
    doc.text("6. Review DNS and subdomain exposure regularly.");
    doc.text("7. Re-scan after remediation to verify security improvement.");

    doc.moveDown(2);
    doc.fontSize(8).fillColor("gray").text(
      "Generated by Security Platform | Automated Security Assessment Report",
      { align: "center" }
    );

    doc.end();

  } catch (error) {
    console.error("Full scan PDF export error:", error);
    res.status(500).send("Failed to generate full scan PDF");
  }
});
app.get("/dynamic-discovery-history", authMiddleware, async (req, res) => {
  try {
    const data =
      req.userRole === "admin"
        ? await DynamicDiscoveryScan.find().sort({ scannedAt: -1 })
        : await DynamicDiscoveryScan.find({ userId: req.userId }).sort({
            scannedAt: -1
          });

    res.json(data);
  } catch (error) {
    res.status(500).json({
      message: "Failed to load dynamic discovery history",
      error: error.message
    });
  }
});




app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});