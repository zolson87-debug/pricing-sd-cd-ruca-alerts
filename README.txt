FILES INCLUDED
- server.js
- package.json
- .node-version
- public/index.html
- data/ruca_by_zip.json (sample file only)

IMPORTANT JSON FILE NAME
Use this exact file name unless you also change the RUCA_FILE environment variable:

ruca_by_zip.json

DEFAULT LOCATION
Place it here inside your repo:

data/ruca_by_zip.json

REQUIRED JSON FORMAT
The file must be a JSON object where:
- each key is a 5-digit ZIP code as text
- each value is the RUCA code as a number from 1 to 10

Example:
{
  "60601": 1,
  "46514": 4,
  "81211": 7,
  "59001": 10
}

RENDER ENVIRONMENT VARIABLES
- SUPERDISPATCH_API_KEY = your Super Dispatch API key
- SUPERDISPATCH_PRICING_URL = https://pricing-insights.superdispatch.com/api/v1/recommended-price
- RUCA_FILE = ./data/ruca_by_zip.json
- NODE_VERSION = 22 (optional if you keep .node-version)

RENDER BUILD / START
Build Command: npm install
Start Command: npm start
Health Check Path: /health

LOCAL TEST
1. open terminal in this folder
2. run: npm install
3. set SUPERDISPATCH_API_KEY in your shell
4. run: npm start
5. open http://localhost:10000
