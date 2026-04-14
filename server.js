// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(process.cwd()));

const SUPERDISPATCH_URL =
  process.env.SUPERDISPATCH_PRICING_URL ||
  "https://pricing-insights.superdispatch.com/api/v1/recommended-price";

const SUPERDISPATCH_API_KEY = process.env.SUPERDISPATCH_API_KEY;
const CD_CLIENT_ID = process.env.CD_CLIENT_ID;
const CD_CLIENT_SECRET = process.env.CD_CLIENT_SECRET;
const CD_TOKEN_URL =
  process.env.CD_TOKEN_URL || "https://id.centraldispatch.com/connect/token";
const CD_PRICING_URL =
  process.env.CD_PRICING_URL ||
  "https://api.centraldispatch.com/market-intelligence/list-prices";

const PRICING_ALERTS_CSV_URL = process.env.PRICING_ALERTS_CSV_URL || "";
const PRICING_REGIONS_CSV_URL = process.env.PRICING_REGIONS_CSV_URL || "";
const DIFFICULT_LANES_CSV_URL = process.env.DIFFICULT_LANES_CSV_URL || "";
const METRO_MAP_CSV_URL = process.env.METRO_MAP_CSV_URL || "";
const KNOWN_ROUTES_CSV_URL = process.env.KNOWN_ROUTES_CSV_URL || "";

const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";

if (!SUPERDISPATCH_API_KEY) {
  console.warn("WARNING: SUPERDISPATCH_API_KEY is not set.");
}
if (!CD_CLIENT_ID || !CD_CLIENT_SECRET) {
  console.warn(
    "WARNING: CD_CLIENT_ID or CD_CLIENT_SECRET is not set. Central Dispatch pricing will be unavailable."
  );
}
if (!APP_USERNAME || !APP_PASSWORD) {
  console.warn("WARNING: APP_USERNAME or APP_PASSWORD is not set.");
}
if (!PRICING_ALERTS_CSV_URL) {
  console.warn(
    "WARNING: PRICING_ALERTS_CSV_URL is not set. Pricing alerts will be unavailable."
  );
}
if (!PRICING_REGIONS_CSV_URL) {
  console.warn(
    "WARNING: PRICING_REGIONS_CSV_URL is not set. Region-based pricing alerts will be unavailable."
  );
}
if (!DIFFICULT_LANES_CSV_URL) {
  console.warn(
    "WARNING: DIFFICULT_LANES_CSV_URL is not set. Difficult lane matching will be unavailable."
  );
}
if (!METRO_MAP_CSV_URL) {
  console.warn(
    "WARNING: METRO_MAP_CSV_URL is not set. Metro mapping will be unavailable."
  );
}
if (!KNOWN_ROUTES_CSV_URL) {
  console.warn(
    "WARNING: KNOWN_ROUTES_CSV_URL is not set. Known route matching will be unavailable."
  );
}

let rucaData = {};
let cdTokenCache = {
  accessToken: null,
  expiresAt: 0
};

let pricingAlertsCache = {
  alerts: [],
  regions: {},
  difficultLanes: [],
  metroMap: {},
  knownRoutes: [],
  fetchedAt: 0
};

const zipGeoCache = {};
const PRICING_ALERTS_CACHE_MS = 5 * 60 * 1000;

try {
  const rucaPath = path.join(__dirname, "ruca_by_zip.json");
  const raw = fs.readFileSync(rucaPath, "utf8");
  rucaData = JSON.parse(raw);
  console.log("RUCA data loaded:", Object.keys(rucaData).length, "ZIP codes");
} catch (err) {
  console.error("Failed to load RUCA file:", err);
}

function normalizeZip(zip) {
  const digits = String(zip || "").replace(/\D/g, "").trim();
  if (!digits) return "";
  return digits.padStart(5, "0").slice(0, 5);
}

function rucaCategory(code) {
  if (code === undefined || code === null || code === "") return "Unknown";
  const n = Number(code);
  if (n >= 1 && n <= 3) return "Metro";
  if (n >= 4 && n <= 6) return "Suburban / Small City";
  if (n >= 7 && n <= 9) return "Rural";
  if (n === 10) return "Very Remote";
  return "Unknown";
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach((part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) return;
    cookies[key] = decodeURIComponent(rest.join("="));
  });

  return cookies;
}

function signSession(username) {
  const payload = JSON.stringify({
    username,
    exp: Date.now() + 1000 * 60 * 60 * 12
  });

  const payloadBase64 = Buffer.from(payload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payloadBase64)
    .digest("base64url");

  return `${payloadBase64}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;

  const [payloadBase64, sig] = token.split(".");
  const expectedSig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payloadBase64)
    .digest("base64url");

  if (sig !== expectedSig) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(payloadBase64, "base64url").toString("utf8")
    );

    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);

  if (!session) {
    const expectsJson =
      req.path === "/quote" ||
      req.path === "/session" ||
      req.headers["content-type"] === "application/json" ||
      (req.headers.accept && req.headers.accept.includes("application/json"));

    if (expectsJson) {
      return res.status(401).json({
        error: "Unauthorized. Please log in again."
      });
    }

    return res.redirect("/login");
  }

  req.user = session;
  next();
}

function toTrimmedString(value) {
  return String(value || "").trim();
}

function normalizeName(value) {
  return String(value || "").trim().toLowerCase();
}

function mapVehicleTypeForCD(vehicleType) {
  const normalized = String(vehicleType || "").trim().toLowerCase();

  if (["sedan", "coupe", "wagon", "car"].includes(normalized)) return "CAR";
  if (normalized === "suv") return "SUV";
  if (normalized === "pickup" || normalized === "truck") return "TRUCK";
  if (normalized === "van") return "VAN";
  return null;
}

function buildCentralDispatchPayload({ pickup, delivery, vehicles, trailer_type }) {
  const stops = [
    {
      stopNumber: 1,
      city: toTrimmedString(pickup?.city),
      state: toTrimmedString(pickup?.state),
      postalCode: normalizeZip(pickup?.zip),
      country: "US"
    },
    {
      stopNumber: 2,
      city: toTrimmedString(delivery?.city),
      state: toTrimmedString(delivery?.state),
      postalCode: normalizeZip(delivery?.zip),
      country: "US"
    }
  ];

  const cdVehicles = (Array.isArray(vehicles) ? vehicles : []).map((vehicle) => {
    const vin = toTrimmedString(vehicle?.vin);
    const year =
      vehicle?.year !== undefined &&
      vehicle?.year !== null &&
      String(vehicle.year).trim() !== ""
        ? String(vehicle.year).trim()
        : "";

    const make = toTrimmedString(vehicle?.make);
    const model = toTrimmedString(vehicle?.model);
    const mappedVehicleType = mapVehicleTypeForCD(vehicle?.type);

    const built = {
      isOperable: !Boolean(vehicle?.is_inoperable),
      pickupStopNumber: 1,
      dropOffStopNumber: 2
    };

    if (vin) {
      built.vin = vin;
    } else {
      if (year) built.year = year;
      if (make) built.make = make;
      if (model) built.model = model;
    }

    if (mappedVehicleType) {
      built.vehicleType = mappedVehicleType;
    }

    return built;
  });

  return {
    stops,
    vehicles: cdVehicles,
    isEnclosed: String(trailer_type || "").toLowerCase() === "enclosed",
    limit: 3
  };
}

function validateCentralDispatchVehicles(cdPayload) {
  const errors = [];
  const vehicles = Array.isArray(cdPayload?.vehicles) ? cdPayload.vehicles : [];

  vehicles.forEach((vehicle, index) => {
    const hasVin = Boolean(toTrimmedString(vehicle?.vin));
    const hasYearMakeModel =
      Boolean(toTrimmedString(vehicle?.year)) &&
      Boolean(toTrimmedString(vehicle?.make)) &&
      Boolean(toTrimmedString(vehicle?.model));

    if (!hasVin && !hasYearMakeModel) {
      errors.push(
        `Vehicle ${index + 1} must have either VIN or Year + Make + Model for Central Dispatch.`
      );
    }
  });

  return errors;
}

async function getCentralDispatchAccessToken() {
  const now = Date.now();

  if (cdTokenCache.accessToken && now < cdTokenCache.expiresAt) {
    return cdTokenCache.accessToken;
  }

  const params = new URLSearchParams({
    client_id: CD_CLIENT_ID,
    client_secret: CD_CLIENT_SECRET,
    grant_type: "client_credentials"
  });

  const response = await fetch(CD_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  });

  const rawText = await response.text();
  let json;

  try {
    json = JSON.parse(rawText);
  } catch {
    throw new Error(
      `Central Dispatch token request did not return valid JSON. Status ${response.status}.`
    );
  }

  if (!response.ok || !json.access_token) {
    const message = json.error_description || json.error || rawText;
    throw new Error(
      `Central Dispatch token request failed (${response.status}): ${message}`
    );
  }

  const expiresInMs =
    Math.max((Number(json.expires_in) || 3600) - 60, 60) * 1000;

  cdTokenCache = {
    accessToken: json.access_token,
    expiresAt: now + expiresInMs
  };

  return cdTokenCache.accessToken;
}

function summarizeCentralDispatchResponse(cdJson) {
  const items = Array.isArray(cdJson?.items) ? cdJson.items : [];

  if (!items.length) {
    return {
      count: 0,
      limit: cdJson?.limit ?? null,
      low: null,
      predicted: null,
      high: null,
      distance_miles: null,
      sample_size: 0,
      predicted_price_per_mile: null
    };
  }

  const first = items[0];

  const rawLow = typeof first.lowPrice === "number" ? first.lowPrice : null;
  const rawPredicted =
    typeof first.meanPredictedPrice === "number" ? first.meanPredictedPrice : null;
  const rawHigh = typeof first.highPrice === "number" ? first.highPrice : null;

  const low = rawLow !== null ? Math.round(rawLow) : null;
  const predicted = rawPredicted !== null ? Math.round(rawPredicted) : null;
  const high = rawHigh !== null ? Math.round(rawHigh) : null;

  const distances = items
    .map((item) => {
      if (typeof item.dispatchDistance === "number") return item.dispatchDistance;
      if (typeof item.listingDistance === "number") return item.listingDistance;
      return null;
    })
    .filter((value) => typeof value === "number");

  const avgDistance =
    distances.length > 0
      ? Math.round(distances.reduce((sum, value) => sum + value, 0) / distances.length)
      : null;

  const predictedPerMile =
    typeof predicted === "number" && typeof avgDistance === "number" && avgDistance > 0
      ? Number((predicted / avgDistance).toFixed(2))
      : null;

  return {
    count: typeof cdJson?.count === "number" ? cdJson.count : items.length,
    limit: typeof cdJson?.limit === "number" ? cdJson.limit : null,
    low,
    predicted,
    high,
    distance_miles: avgDistance,
    sample_size: items.length,
    predicted_price_per_mile: predictedPerMile
  };
}

function splitCsvLine(line) {
  const result = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];

    if (char === '"') {
      if (inQuotes && next === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }

  result.push(current);
  return result;
}

function parseSimpleCsv(text) {
  const lines = String(text || "")
    .replace(/\r/g, "")
    .split("\n")
    .filter((line) => line.trim() !== "");

  if (!lines.length) return [];

  const headers = splitCsvLine(lines[0]).map((h) => h.trim());

  return lines.slice(1).map((line) => {
    const values = splitCsvLine(line);
    const row = {};

    headers.forEach((header, index) => {
      row[header] = (values[index] || "").trim();
    });

    return row;
  });
}

async function loadSheetRows(csvUrl) {
  if (!csvUrl) return [];

  const response = await fetch(csvUrl);
  if (!response.ok) {
    throw new Error(`Failed to load sheet CSV: ${response.status}`);
  }

  const text = await response.text();
  return parseSimpleCsv(text);
}

async function loadPricingRulesAndRegions() {
  const now = Date.now();

  if (now - pricingAlertsCache.fetchedAt < PRICING_ALERTS_CACHE_MS) {
    return pricingAlertsCache;
  }

  const [
    alertRows,
    regionRows,
    difficultLaneRows,
    metroMapRows,
    knownRouteRows
  ] = await Promise.all([
    loadSheetRows(PRICING_ALERTS_CSV_URL),
    loadSheetRows(PRICING_REGIONS_CSV_URL),
    loadSheetRows(DIFFICULT_LANES_CSV_URL),
    loadSheetRows(METRO_MAP_CSV_URL),
    loadSheetRows(KNOWN_ROUTES_CSV_URL)
  ]);

  const regions = {};
  regionRows.forEach((row) => {
    const name = String(row.region_name || "").trim();
    const states = String(row.states_csv || "")
      .split(",")
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);

    if (name) {
      regions[name] = states;
    }
  });

  const metroMap = {};
  metroMapRows.forEach((row) => {
    const active = ["yes", "true", "1", "active", ""].includes(
      String(row.active || "").trim().toLowerCase()
    );
    if (!active) return;

    const zip = normalizeZip(row.zip);
    const metroArea = String(row.metro_area || "").trim();

    if (zip && metroArea) {
      metroMap[zip] = metroArea;
    }
  });

  pricingAlertsCache = {
    alerts: alertRows,
    regions,
    difficultLanes: difficultLaneRows,
    metroMap,
    knownRoutes: knownRouteRows,
    fetchedAt: now
  };

  return pricingAlertsCache;
}

function isActiveRule(row) {
  return ["yes", "true", "1", "active"].includes(
    String(row.active || "").trim().toLowerCase()
  );
}

function normalizeDateOnly(value) {
  const v = String(value || "").trim();
  return v || null;
}

function dateInRange(today, startDate, endDate) {
  const start = normalizeDateOnly(startDate);
  const end = normalizeDateOnly(endDate);

  if (start && today < start) return false;
  if (end && today > end) return false;
  return true;
}

function matchesState(ruleValue, actualState) {
  const rule = String(ruleValue || "").trim().toUpperCase();
  if (!rule) return true;
  return rule === String(actualState || "").trim().toUpperCase();
}

function matchesRegion(ruleValue, actualState, regions) {
  const rule = String(ruleValue || "").trim().toLowerCase();
  if (!rule) return true;

  const matchedKey = Object.keys(regions).find(
    (key) => String(key || "").trim().toLowerCase() === rule
  );

  if (!matchedKey) return false;

  const regionStates = regions[matchedKey] || [];
  return regionStates.includes(String(actualState || "").trim().toUpperCase());
}

function matchesVehicleType(ruleValue, actualVehicleType) {
  const rule = String(ruleValue || "").trim().toLowerCase();
  if (!rule) return true;
  return rule === String(actualVehicleType || "").trim().toLowerCase();
}

function matchesTrailerType(ruleValue, actualTrailerType) {
  const rule = String(ruleValue || "").trim().toLowerCase();
  if (!rule) return true;
  return rule === String(actualTrailerType || "").trim().toLowerCase();
}

function findMatchingPricingAlerts({ alerts, regions, pickup, delivery, vehicles, trailer_type }) {
  const today = new Date().toISOString().slice(0, 10);
  const firstVehicle = Array.isArray(vehicles) && vehicles.length ? vehicles[0] : {};
  const vehicleType = firstVehicle?.type || "";

  return alerts
    .filter((row) => isActiveRule(row))
    .filter((row) => dateInRange(today, row.start_date, row.end_date))
    .filter((row) => matchesState(row.origin_state, pickup?.state))
    .filter((row) => matchesRegion(row.origin_region, pickup?.state, regions))
    .filter((row) => matchesState(row.destination_state, delivery?.state))
    .filter((row) => matchesRegion(row.destination_region, delivery?.state, regions))
    .filter((row) => matchesVehicleType(row.vehicle_type, vehicleType))
    .filter((row) => matchesTrailerType(row.trailer_type, trailer_type))
    .sort((a, b) => Number(a.sort_order || 9999) - Number(b.sort_order || 9999))
    .map((row) => ({
      rule_name: row.rule_name || "Pricing Alert",
      severity: String(row.severity || "info").trim().toLowerCase(),
      alert_message: row.alert_message || "",
      pricing_guidance: row.pricing_guidance || ""
    }));
}

function isActiveDifficultLaneRow(row) {
  return ["yes", "true", "1", "active"].includes(
    String(row.active || "").trim().toLowerCase()
  );
}

function toRadians(deg) {
  return (Number(deg) * Math.PI) / 180;
}

function haversineMiles(lat1, lon1, lat2, lon2) {
  const R = 3958.8;
  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

async function lookupZipLatLng(zip) {
  const cleanZip = normalizeZip(zip);

  if (!/^\d{5}$/.test(cleanZip)) {
    return null;
  }

  if (Object.prototype.hasOwnProperty.call(zipGeoCache, cleanZip)) {
    return zipGeoCache[cleanZip];
  }

  try {
    const response = await fetch(`https://api.zippopotam.us/us/${cleanZip}`);
    if (!response.ok) {
      zipGeoCache[cleanZip] = null;
      return null;
    }

    const data = await response.json();
    const place = data?.places?.[0];
    if (!place) {
      zipGeoCache[cleanZip] = null;
      return null;
    }

    const lat = Number(place.latitude);
    const lng = Number(place.longitude);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      zipGeoCache[cleanZip] = null;
      return null;
    }

    const result = { zip: cleanZip, lat, lng };
    zipGeoCache[cleanZip] = result;
    return result;
  } catch {
    zipGeoCache[cleanZip] = null;
    return null;
  }
}

async function findMatchingDifficultLane(difficultLanes, pickupZip, deliveryZip) {
  const emptyResult = {
    matched: false,
    pickup_side_match: false,
    dropoff_side_match: false,
    pickup_matches: [],
    dropoff_matches: [],
    full_lane_matches: []
  };

  if (!Array.isArray(difficultLanes) || difficultLanes.length === 0) {
    return emptyResult;
  }

  const normalizedPickupZip = normalizeZip(pickupZip);
  const normalizedDeliveryZip = normalizeZip(deliveryZip);

  const pickupPoint = await lookupZipLatLng(normalizedPickupZip);
  const deliveryPoint = await lookupZipLatLng(normalizedDeliveryZip);

  if (!pickupPoint || !deliveryPoint) {
    return emptyResult;
  }

  const pickupMatches = [];
  const dropoffMatches = [];
  const fullLaneMatches = [];
  const activeRows = difficultLanes.filter((row) => isActiveDifficultLaneRow(row));

  for (const row of activeRows) {
    const originZip = normalizeZip(row.origin_zip);
    const destinationZip = normalizeZip(row.destination_zip);

    if (!/^\d{5}$/.test(originZip) || !/^\d{5}$/.test(destinationZip)) {
      continue;
    }

    const originPoint = await lookupZipLatLng(originZip);
    const destinationPoint = await lookupZipLatLng(destinationZip);

    if (!originPoint || !destinationPoint) {
      continue;
    }

    const originMiles = haversineMiles(
      pickupPoint.lat,
      pickupPoint.lng,
      originPoint.lat,
      originPoint.lng
    );

    const destinationMiles = haversineMiles(
      deliveryPoint.lat,
      deliveryPoint.lng,
      destinationPoint.lat,
      destinationPoint.lng
    );

    const pickupSideMatch = originMiles <= 25;
    const dropoffSideMatch = destinationMiles <= 25;

    if (pickupSideMatch) {
      pickupMatches.push({
        rule_name: row.rule_name || "Difficult Pickup Area",
        alert_message:
          row.alert_message ||
          "Pickup ZIP is within 25 miles of a known difficult-lane origin.",
        pricing_guidance:
          row.pricing_guidance ||
          "Review pricing carefully and consider adding margin.",
        matched_zip: originZip,
        miles: Number(originMiles.toFixed(1))
      });
    }

    if (dropoffSideMatch) {
      dropoffMatches.push({
        rule_name: row.rule_name || "Difficult Dropoff Area",
        alert_message:
          row.alert_message ||
          "Dropoff ZIP is within 25 miles of a known difficult-lane destination.",
        pricing_guidance:
          row.pricing_guidance ||
          "Review pricing carefully and consider adding margin.",
        matched_zip: destinationZip,
        miles: Number(destinationMiles.toFixed(1))
      });
    }

    if (pickupSideMatch && dropoffSideMatch) {
      fullLaneMatches.push({
        rule_name: row.rule_name || "Known Difficult Lane",
        alert_message:
          row.alert_message ||
          "This quote matches a known difficult lane within 25 miles on both ends.",
        pricing_guidance:
          row.pricing_guidance ||
          "Review pricing carefully and consider adding margin.",
        origin_zip: originZip,
        destination_zip: destinationZip,
        origin_miles: Number(originMiles.toFixed(1)),
        destination_miles: Number(destinationMiles.toFixed(1))
      });
    }
  }

  return {
    matched: fullLaneMatches.length > 0,
    pickup_side_match: pickupMatches.length > 0,
    dropoff_side_match: dropoffMatches.length > 0,
    pickup_matches: pickupMatches,
    dropoff_matches: dropoffMatches,
    full_lane_matches: fullLaneMatches
  };
}

function findMatchingKnownRoute({ metroMap, knownRoutes, pickupZip, deliveryZip }) {
  const pickupMetro = metroMap[normalizeZip(pickupZip)] || "";
  const deliveryMetro = metroMap[normalizeZip(deliveryZip)] || "";

  const emptyResult = {
    matched: false,
    pickup_metro: pickupMetro || null,
    delivery_metro: deliveryMetro || null,
    matches: []
  };

  if (!pickupMetro || !deliveryMetro) {
    return emptyResult;
  }

  const matches = (Array.isArray(knownRoutes) ? knownRoutes : [])
    .filter((row) => isActiveRule(row))
    .filter(
      (row) =>
        normalizeName(row.origin_metro) === normalizeName(pickupMetro) &&
        normalizeName(row.destination_metro) === normalizeName(deliveryMetro)
    )
    .map((row) => ({
      rule_name: row.rule_name || "Known Route",
      alert_message:
        row.alert_message || `Known route detected: ${pickupMetro} → ${deliveryMetro}.`,
      pricing_guidance:
        row.pricing_guidance ||
        "Review prior performance and route pricing history.",
      pickup_metro: pickupMetro,
      delivery_metro: deliveryMetro
    }));

  return {
    matched: matches.length > 0,
    pickup_metro: pickupMetro,
    delivery_metro: deliveryMetro,
    matches
  };
}

function dedupeAlerts(alerts) {
  const seen = new Set();

  return alerts.filter((alert) => {
    const key = [
      String(alert.rule_name || "").trim(),
      String(alert.severity || "").trim(),
      String(alert.alert_message || "").trim(),
      String(alert.pricing_guidance || "").trim()
    ].join("|");

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

app.get("/login", (req, res) => {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);

  if (session) {
    return res.redirect("/");
  }

  return res.sendFile(path.resolve(process.cwd(), "login.html"));
});

app.post("/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!APP_USERNAME || !APP_PASSWORD) {
    return res
      .status(500)
      .send("Server auth environment variables are not configured.");
  }

  if (username !== APP_USERNAME || password !== APP_PASSWORD) {
    return res.redirect("/login?error=1");
  }

  const token = signSession(username);
  const isProduction = process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `auth_session=${encodeURIComponent(
      token
    )}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200${
      isProduction ? "; Secure" : ""
    }`
  );

  res.redirect("/");
});

app.post("/logout", (req, res) => {
  const isProduction = process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `auth_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${
      isProduction ? "; Secure" : ""
    }`
  );

  res.redirect("/login");
});

app.get("/health", (req, res) => {
  res.type("text/plain").send("OK");
});

app.get("/", requireAuth, (req, res) => {
  return res.sendFile(path.resolve(process.cwd(), "index.html"));
});

app.get("/session", requireAuth, (req, res) => {
  res.json({
    authenticated: true,
    username: req.user.username
  });
});

app.post("/quote", requireAuth, async (req, res) => {
  try {
    const { pickup, delivery, vehicles, trailer_type } = req.body || {};

    if (!pickup?.zip || !delivery?.zip) {
      return res.status(400).json({
        error: "Pickup ZIP and delivery ZIP are required."
      });
    }

    if (!SUPERDISPATCH_API_KEY) {
      return res.status(500).json({
        error:
          "Server misconfigured: SUPERDISPATCH_API_KEY is not set on the server."
      });
    }

    const pickupZip = normalizeZip(pickup.zip);
    const dropZip = normalizeZip(delivery.zip);

    const pickupRuca = rucaData[pickupZip];
    const dropRuca = rucaData[dropZip];

    let pricingAlerts = [];
    let difficultLaneMatch = {
      matched: false,
      pickup_side_match: false,
      dropoff_side_match: false,
      pickup_matches: [],
      dropoff_matches: [],
      full_lane_matches: []
    };

    let knownRouteMatch = {
      matched: false,
      pickup_metro: null,
      delivery_metro: null,
      matches: []
    };

    try {
      const ruleData = await loadPricingRulesAndRegions();

      pricingAlerts = findMatchingPricingAlerts({
        alerts: ruleData.alerts,
        regions: ruleData.regions,
        pickup: {
          ...pickup,
          zip: pickupZip
        },
        delivery: {
          ...delivery,
          zip: dropZip
        },
        vehicles,
        trailer_type
      });

      difficultLaneMatch = await findMatchingDifficultLane(
        ruleData.difficultLanes,
        pickupZip,
        dropZip
      );

      difficultLaneMatch.full_lane_matches.forEach((match) => {
        pricingAlerts.push({
          rule_name: match.rule_name,
          severity: "high",
          alert_message: match.alert_message,
          pricing_guidance: `${match.pricing_guidance} Matched base lane ${match.origin_zip} → ${match.destination_zip}. Origin within ${match.origin_miles} miles and destination within ${match.destination_miles} miles.`
        });
      });

      difficultLaneMatch.pickup_matches.forEach((match) => {
        pricingAlerts.push({
          rule_name: "Difficult Pickup Area",
          severity: "medium",
          alert_message: `Pickup ZIP is within ${match.miles} miles of known difficult origin ZIP ${match.matched_zip}.`,
          pricing_guidance: match.pricing_guidance
        });
      });

      difficultLaneMatch.dropoff_matches.forEach((match) => {
        pricingAlerts.push({
          rule_name: "Difficult Dropoff Area",
          severity: "medium",
          alert_message: `Dropoff ZIP is within ${match.miles} miles of known difficult destination ZIP ${match.matched_zip}.`,
          pricing_guidance: match.pricing_guidance
        });
      });

      knownRouteMatch = findMatchingKnownRoute({
        metroMap: ruleData.metroMap,
        knownRoutes: ruleData.knownRoutes,
        pickupZip,
        deliveryZip: dropZip
      });

      knownRouteMatch.matches.forEach((match) => {
        pricingAlerts.push({
          rule_name: match.rule_name,
          severity: "low",
          alert_message: match.alert_message,
          pricing_guidance: `${match.pricing_guidance} Route detected: ${match.pickup_metro} → ${match.delivery_metro}.`
        });
      });

      pricingAlerts = dedupeAlerts(pricingAlerts);
    } catch (err) {
      console.error(
        "Failed to load pricing alerts / difficult lanes / known routes:",
        err.message
      );
    }

    const normalizedPickup = {
      ...pickup,
      zip: pickupZip
    };

    const normalizedDelivery = {
      ...delivery,
      zip: dropZip
    };

    const sdPromise = fetch(SUPERDISPATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": SUPERDISPATCH_API_KEY
      },
      body: JSON.stringify({
        pickup: normalizedPickup,
        delivery: normalizedDelivery,
        vehicles,
        trailer_type
      })
    });

    const canCallCentralDispatch = Boolean(CD_CLIENT_ID && CD_CLIENT_SECRET);
    const cdPayload = buildCentralDispatchPayload({
      pickup: normalizedPickup,
      delivery: normalizedDelivery,
      vehicles,
      trailer_type
    });
    const cdValidationErrors = validateCentralDispatchVehicles(cdPayload);

    let cdPromise = null;
    if (canCallCentralDispatch && cdValidationErrors.length === 0) {
      cdPromise = (async () => {
        const token = await getCentralDispatchAccessToken();

        return fetch(CD_PRICING_URL, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/vnd.coxauto.v1+json"
          },
          body: JSON.stringify(cdPayload)
        });
      })();
    }

    const sdResponse = await sdPromise;
    const sdRawText = await sdResponse.text();

    let sdJson;
    try {
      sdJson = JSON.parse(sdRawText);
    } catch {
      return res.status(502).json({
        error: "Super Dispatch did not return valid JSON.",
        status: sdResponse.status,
        raw_response_preview: sdRawText.slice(0, 500)
      });
    }

    let centraldispatch = {
      enabled: canCallCentralDispatch,
      request_payload: cdPayload,
      summary: null,
      data: null,
      error: null,
      status: null
    };

    if (canCallCentralDispatch && cdPromise) {
      try {
        const cdResponse = await cdPromise;
        const cdRawText = await cdResponse.text();
        centraldispatch.status = cdResponse.status;

        let cdJson = null;
        try {
          cdJson = JSON.parse(cdRawText);
        } catch {
          centraldispatch.error = {
            message: "Central Dispatch did not return valid JSON.",
            raw_response_preview: cdRawText.slice(0, 500)
          };
        }

        if (cdJson) {
          if (cdResponse.ok) {
            centraldispatch.data = cdJson;
            centraldispatch.summary = summarizeCentralDispatchResponse(cdJson);
          } else {
            centraldispatch.error = cdJson;
          }
        }
      } catch (err) {
        centraldispatch.error = { message: err.message };
      }
    } else {
      centraldispatch.error = !canCallCentralDispatch
        ? {
            message:
              "Central Dispatch credentials are not configured on the server. Set CD_CLIENT_ID and CD_CLIENT_SECRET to enable CD pricing."
          }
        : {
            message: "Central Dispatch vehicle validation failed before API call.",
            details: cdValidationErrors
          };
    }

    return res.status(sdResponse.status).json({
      superdispatch: sdJson,
      centraldispatch,
      pricing_alerts: pricingAlerts,
      known_difficult_lane: difficultLaneMatch,
      known_route: knownRouteMatch,
      metro_areas: {
        pickup_metro: knownRouteMatch.pickup_metro,
        delivery_metro: knownRouteMatch.delivery_metro
      },
      pickup_access: {
        zip: pickupZip,
        ruca_code: pickupRuca ?? null,
        ruca_category: rucaCategory(pickupRuca)
      },
      dropoff_access: {
        zip: dropZip,
        ruca_code: dropRuca ?? null,
        ruca_category: rucaCategory(dropRuca)
      }
    });
  } catch (err) {
    console.error("Quote route error:", err);

    return res.status(500).json({
      error: "Server error",
      details: err.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
