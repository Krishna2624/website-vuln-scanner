const mongoose = require("mongoose");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const cheerio = require("cheerio");
const sslChecker = require("ssl-checker").default;
const PDFDocument = require("pdfkit");
const dnsModule = require("dns");
dnsModule.setServers(["8.8.8.8", "1.1.1.1"]);
const dns = dnsModule.promises;
const net = require("net");
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
  results: [
    {
      port: Number,
      service: String,
      status: String,
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

function getCveForService(service, port, status) {
  if (status !== "Open") {
    return {
      cveId: "N/A",
      cveSeverity: "None",
      cvssScore: "N/A",
      cveDescription: "No CVE mapping for closed ports.",
      cveRecommendation: "No action required."
    };
  }

  const serviceName = service.toLowerCase();

  if (serviceName.includes("ssh") || port === 22) {
    return {
      cveId: "CVE-2024-6387",
      cveSeverity: "Critical",
      cvssScore: "9.8",
      cveDescription: "Known OpenSSH race condition vulnerability reference.",
      cveRecommendation: "Patch OpenSSH immediately and restrict SSH access."
    };
  }

  if (serviceName.includes("mysql") || port === 3306) {
    return {
      cveId: "CVE-2023-21980",
      cveSeverity: "High",
      cvssScore: "8.1",
      cveDescription: "Known MySQL vulnerability reference.",
      cveRecommendation: "Restrict database exposure and apply security updates."
    };
  }

  if (serviceName.includes("redis") || port === 6379) {
    return {
      cveId: "CVE-2022-0543",
      cveSeverity: "Critical",
      cvssScore: "10.0",
      cveDescription: "Known Redis Lua sandbox escape vulnerability reference.",
      cveRecommendation: "Do not expose Redis publicly. Patch immediately."
    };
  }

  if (serviceName.includes("telnet") || port === 23) {
    return {
      cveId: "Legacy insecure protocol",
      cveSeverity: "Critical",
      cvssScore: "N/A",
      cveDescription: "Telnet transmits credentials in clear text.",
      cveRecommendation: "Disable Telnet and use SSH instead."
    };
  }

  return {
    cveId: "No direct CVE mapped",
    cveSeverity: "Low",
    cvssScore: "N/A",
    cveDescription: "No demo CVE mapped for this service.",
    cveRecommendation: "Keep the service patched and monitor advisories."
  };
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

    const technologies = {
      server: headers["server"] || "Hidden / Not detected",
      poweredBy: headers["x-powered-by"] || "Hidden / Not detected",
      frameworkHints: []
    };

    if (html.includes("wp-content")) technologies.frameworkHints.push("WordPress");
    if (html.toLowerCase().includes("react")) technologies.frameworkHints.push("React");
    if (html.toLowerCase().includes("vue")) technologies.frameworkHints.push("Vue");
    if (html.toLowerCase().includes("angular")) technologies.frameworkHints.push("Angular");

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
    const { target } = req.body;

    if (!target) {
      return res.status(400).json({ message: "Target is required" });
    }

    const cleanTarget = target
      .replace("https://", "")
      .replace("http://", "")
      .replace("www.", "")
      .split("/")[0]
      .trim();

    const results = [];

    for (const item of commonPorts) {
      const status = await scanPort(cleanTarget, item.port);
      const cveInfo = getCveForService(item.service, item.port, status);

      results.push({
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

    const savedScan = await PortScan.create({
      userId: req.userId,
      target: cleanTarget,
      scannedAt: new Date(),
      results
    });

    res.json(savedScan);

  } catch (error) {
    console.error("Port scan error:", error);
    res.status(500).json({ message: "Port scan failed" });
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
        resolvedIPs,
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
const resolvedIPs = await dns.resolve4(domain).catch(() => []);
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

    const savedWhois = await WhoisScan.create({
      ...finalData,
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
      domain: req.body.domain,
      subdomains: [],
      totalFound: 0,
      source: "crt.sh timeout or unavailable",
      scannedAt: new Date()
    });

    res.json(savedScan);
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

    const technologies = {
      server: headers["server"] || "Hidden / Not detected",
      poweredBy: headers["x-powered-by"] || "Hidden / Not detected",
      frameworkHints: []
    };

    if (html.includes("wp-content")) technologies.frameworkHints.push("WordPress");
    if (html.toLowerCase().includes("react")) technologies.frameworkHints.push("React");
    if (html.toLowerCase().includes("vue")) technologies.frameworkHints.push("Vue");
    if (html.toLowerCase().includes("angular")) technologies.frameworkHints.push("Angular");

    // 2. DNS Lookup
    const dnsLookup = await runDnsLookupModule(targetUrl);

    // 3. Port Scan + CVE
    const portResults = [];

    for (const item of commonPorts) {
      const status = await scanPort(domain, item.port);
      const cveInfo = getCveForService(item.service, item.port, status);

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

    // 4. WHOIS basic reuse
    let whoisData = {
      domain,
      registrar: "Run separate WHOIS for detailed data",
      creationDate: "Not Available",
      expirationDate: "Not Available",
      nameServers: [],
      status: "Included in full scan summary"
    };

    // 5. Subdomain basic placeholder
    let subdomainData = {
      domain,
      subdomains: [],
      totalFound: 0,
      source: "Use detailed subdomain module for full CT log results"
    };

    const fullReport = {
      userId: req.userId,
      reportType: "Full Security Scan",
      target: targetUrl,
      domain,
      scannedAt: new Date(),

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


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});