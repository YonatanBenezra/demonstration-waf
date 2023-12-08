const express = require("express");
const rateLimit = require("express-rate-limit");
const { check, validationResult } = require("express-validator");
const cors = require("cors");
const geoip = require("geoip-lite");

const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 3000;

// Rate limiting to prevent DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Rate limiting to prevent DoS attacks
const DDOSlimiter = rateLimit({
  windowMs: 1 * 60 * 100, // 10 seconds window
  max: 20, // limit each IP to 20 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    const ip = req.ip;
    const geo = geoip.lookup(ip);
    res.status(429).json({
      message: "Too many requests, please try again later.",
      ip: ip,
      geoLocation: geo ? `${geo.city}, ${geo.country}` : "Not available",
    });
  },
});
app.use(DDOSlimiter);

// Global rate limiting configuration
const Globallimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 200, // limit the total number of requests per minute to 2000
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    const ip = req.ip;
    const geo = geoip.lookup(ip);
    res.status(429).json({
      message: "Too many requests, please try again later.",
      ip: ip,
      geoLocation: geo ? `${geo.city}, ${geo.country}` : "Not available",
    });
  },
});
app.use(Globallimiter);

app.post("/filter-request", (req, res) => {
  const { content } = req.body;
  const threatType = detectMaliciousActivity(content, req);

  if (threatType) {
    const ip = req.ip; // Get IP address from the request
    const geo = geoip.lookup(ip) || {}; // Get geolocation data

    const response = {
      message: `Malicious request detected: ${threatType}`,
      ip: ip,
      geoLocation: geo.city ? `${geo.city}, ${geo.country}` : "Not available",
    };

    console.log("Malicious request detected:", response);
    return res.status(400).json(response);
  }

  res.json({ message: "Request is safe" });
});

function detectMaliciousActivity(content, req) {
  // Check for XSS
  if (/<script.*?>.*?<\/script>/i.test(content)) return "XSS Attack";

  // Check for SQL Injection (extended)
  const sqlInjectionPatterns = [
    {
      pattern: /SELECT|INSERT|DELETE|DROP|UPDATE|UNION|CREATE|ALTER/i,
      type: "Standard SQL Injection",
    },
    { pattern: /OR\s+1=1/, type: "Basic SQL Injection" },
    { pattern: /';\s*--/, type: "SQL Comment Sequence Injection" },
    {
      pattern: /';\s*WAITFOR\s+DELAY\s+'[^']+'/,
      type: "Time-based SQL Injection",
    },
    {
      pattern: /';\s*IF\s*\(.*\)\s*,\s*SLEEP\s*\(.+\)\s*,.*/,
      type: "Conditional SQL Injection",
    },
    { pattern: /';\s*EXEC\s*\(.+\)/, type: "SQL Execution Command Injection" },
  ];

  for (let { pattern, type } of sqlInjectionPatterns) {
    if (pattern.test(content)) return type;
  }

  // Check for LFI
  if (/\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/hosts/i.test(content))
    return "Local File Inclusion";

  // Additional checks for other types can be added here

  return false;
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
