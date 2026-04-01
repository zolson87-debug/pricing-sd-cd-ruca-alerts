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

let rucaData = {};
let cdTokenCache = {
  accessToken: null,
  expiresAt: 0
};

try {
  const rucaPath = path.join(__dirname, "ruca_by_zip.json");
  const raw = fs.readFileSync(rucaPath, "utf8");
  rucaData = JSON.parse(raw);
  console.log("RUCA data loaded:", Object.keys(rucaData).length, "ZIP codes");
} catch (err) {
  console.error("Failed to load RUCA file:", err);
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
    return res.redirect("/login");
  }

  req.user = session;
  next();
}

function toTrimmedString(value) {
  return String(value || "").trim();
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
      postalCode: toTrimmedString(pickup?.zip),
      country: "US"
    },
    {
      stopNumber: 2,
      city: toTrimmedString(delivery?.city),
      state: toTrimmedString(delivery?.state),
      postalCode: toTrimmedString(delivery?.zip),
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

  const rawLow =
    typeof first.lowPrice === "number" ? first.lowPrice : null;
  const rawPredicted =
    typeof first.meanPredictedPrice === "number" ? first.meanPredictedPrice : null;
  const rawHigh =
    typeof first.highPrice === "number" ? first.highPrice : null;

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

    const pickupZip = String(pickup.zip).trim();
    const dropZip = String(delivery.zip).trim();

    const pickupRuca = rucaData[pickupZip];
    const dropRuca = rucaData[dropZip];

    const sdPromise = fetch(SUPERDISPATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": SUPERDISPATCH_API_KEY
      },
      body: JSON.stringify({
        pickup,
        delivery,
        vehicles,
        trailer_type
      })
    });

    const canCallCentralDispatch = Boolean(CD_CLIENT_ID && CD_CLIENT_SECRET);
    const cdPayload = buildCentralDispatchPayload({
      pickup,
      delivery,
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
