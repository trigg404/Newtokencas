/**
 * New Token Volume Scanner — HIGH RISK, SEPARATE DEPLOYMENT
 * ===========================================================
 * TWO discovery feeds + automated safety checking:
 *
 *  FEED A — GeckoTerminal new pools (free) — catches tokens AFTER a
 *    liquidity pool exists, across Ethereum/Base/Solana/BSC/Arbitrum.
 *
 *  FEED B — pump.fun via PumpPortal WebSocket (free) — catches Solana
 *    tokens at CREATION, before they even have a DEX pool (bonding
 *    curve stage). Earlier signal than Feed A for Solana specifically.
 *
 *  SAFETY CHECK — GoPlus Security API (free, official, used by
 *    MetaMask/Trust Wallet/Binance) — for EVM-chain tokens, checks
 *    actual contract risk (honeypot status, sell tax, mint function,
 *    creator holding %) before alerting, instead of guessing from
 *    volume/liquidity patterns alone. Solana safety-checking isn't
 *    automated yet (GoPlus's Solana support is still Beta) — those
 *    alerts note to verify manually via RugCheck.xyz.
 *
 * ⚠️  THIS IS THE HIGHEST-RISK TOOL IN THE SIGNAL STACK. ⚠️
 * The large majority of brand-new tokens are rug pulls, honeypots, or
 * abandoned within hours. These filters reduce SOME noise and catch
 * SOME scams, but do not and cannot make this safe. Every alert
 * includes a reminder. Deployed separately from the other, lower-risk
 * scanners so it can be muted/ignored independently.
 *
 * Env vars:
 *   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID  (use a SEPARATE bot/chat from
 *     your other scanners — that's the whole point of this deployment)
 *   POLL_MINUTES          (default 5 — GeckoTerminal poll interval)
 *   MIN_LIQUIDITY_USD     (default 5000  — pools below this are ignored)
 *   MAX_AGE_HOURS         (default 6     — only alert on genuinely new pools)
 *   MIN_VOL_LIQ_RATIO     (default 0.5   — 24h volume must be at least this
 *                          fraction of liquidity to count as a real spike)
 *   CHAINS                (default "eth,base,solana,bsc,arbitrum" — comma list)
 *   ENABLE_PUMPFUN        (default true — set false to disable Feed B)
 *   PUMPPORTAL_API_KEY    (optional — free tier works without one for
 *                          the new-token subscription specifically)
 *   PUMPFUN_MIN_INITIAL_BUY_SOL (default 1 — ignore tiny/no-conviction launches)
 */

require("dotenv").config();
const https = require("https");
let WebSocket;
try { WebSocket = require("ws"); } catch (e) { WebSocket = null; }

const CONFIG = {
  telegram: {
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
  pollMs: (parseInt(process.env.POLL_MINUTES || "5")) * 60 * 1000,
  minLiquidityUsd: parseFloat(process.env.MIN_LIQUIDITY_USD || "5000"),
  maxAgeHours: parseFloat(process.env.MAX_AGE_HOURS || "6"),
  minVolLiqRatio: parseFloat(process.env.MIN_VOL_LIQ_RATIO || "0.5"),
  chains: (process.env.CHAINS || "eth,base,solana,bsc,arbitrum").split(",").map(s => s.trim()),
  enablePumpfun: process.env.ENABLE_PUMPFUN !== "false",
  pumpportalApiKey: process.env.PUMPPORTAL_API_KEY || "",
  pumpfunMinInitialBuySol: parseFloat(process.env.PUMPFUN_MIN_INITIAL_BUY_SOL || "1"),
  minBuySellRatio: parseFloat(process.env.MIN_BUY_SELL_RATIO || "3"),
  minHolderGrowthPct: parseFloat(process.env.MIN_HOLDER_GROWTH_PCT || "0.10"),
  maxWatchMinutes: parseFloat(process.env.MAX_WATCH_MINUTES || "45"),
};

// GoPlus chain-id mapping for the EVM chains we support (Solana omitted —
// GoPlus's Solana endpoint is still Beta, not wired in here to avoid
// giving false confidence on an unverified integration)
const GOPLUS_CHAIN_IDS = { eth: "1", bsc: "56", arbitrum: "42161", base: "8453" };

const CHAIN_LABELS = {
  eth: "Ethereum", base: "Base", solana: "Solana", bsc: "BSC",
  arbitrum: "Arbitrum", polygon_pos: "Polygon", avax: "Avalanche",
};

// ─── HTTP helper ──────────────────────────────────────────────────────────────
function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { "User-Agent": "NewTokenScanner/1.0", "Accept": "application/json" },
      timeout: 20000,
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, body: null }); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
  });
}

function sendTelegram(text) {
  return new Promise((resolve) => {
    if (!CONFIG.telegram.botToken || !CONFIG.telegram.chatId) {
      console.warn("⚠️  Telegram not configured."); return resolve();
    }
    const body = JSON.stringify({
      chat_id: CONFIG.telegram.chatId,
      text: text.slice(0, 4000),
      parse_mode: "Markdown",
      disable_notification: false,
      disable_web_page_preview: true,
    });
    const req = https.request(
      `https://api.telegram.org/bot${CONFIG.telegram.botToken}/sendMessage`,
      { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => {
        let data = "";
        res.on("data", c => data += c);
        res.on("end", () => {
          try { const r = JSON.parse(data); if (!r.ok) console.error("❌ Telegram:", r.description); } catch (e) {}
          resolve();
        });
      }
    );
    req.on("error", () => resolve());
    req.write(body);
    req.end();
  });
}

// ─── Pool fetching + evaluation ──────────────────────────────────────────────
async function fetchNewPools(chain) {
  const url = `https://api.geckoterminal.com/api/v2/networks/${chain}/new_pools`;
  try {
    const { status, body } = await httpGetJson(url);
    if (status !== 200 || !body?.data) {
      console.warn(`   ⚠️  ${CHAIN_LABELS[chain] || chain}: HTTP ${status} or no data`);
      return [];
    }
    return body.data;
  } catch (e) {
    console.warn(`   ⚠️  ${CHAIN_LABELS[chain] || chain}: ${e.message}`);
    return [];
  }
}

function evaluatePool(pool, chain) {
  const a = pool.attributes;
  const liquidity = parseFloat(a.reserve_in_usd || "0");
  const volume24h = parseFloat(a.volume_usd?.h24 || "0");
  const volume1h = parseFloat(a.volume_usd?.h1 || "0");
  const createdAt = a.pool_created_at ? new Date(a.pool_created_at) : null;
  const ageHours = createdAt ? (Date.now() - createdAt.getTime()) / 3600000 : Infinity;
  const ratio = liquidity > 0 ? volume24h / liquidity : 0;
  const fdv = parseFloat(a.fdv_usd || "0");
  const priceChange1h = parseFloat(a.price_change_percentage?.h1 || "0");
  const priceChange24h = parseFloat(a.price_change_percentage?.h24 || "0");
  const buys1h = a.transactions?.h1?.buys || 0;
  const sells1h = a.transactions?.h1?.sells || 0;
  const buySellRatio = buys1h / Math.max(sells1h, 1);

  const passes = liquidity >= CONFIG.minLiquidityUsd
    && ageHours <= CONFIG.maxAgeHours
    && ratio >= CONFIG.minVolLiqRatio
    && buySellRatio >= CONFIG.minBuySellRatio;

  return {
    passes, chain, name: a.name, address: a.address,
    liquidity, volume24h, volume1h, ageHours, ratio, fdv,
    priceChange1h, priceChange24h, buys1h, sells1h, buySellRatio,
    poolId: pool.id,
  };
}

// ─── Contract safety check (GoPlus Security, EVM chains only) ────────────────
async function checkTokenSafety(tokenAddress, chain) {
  const goplusChainId = GOPLUS_CHAIN_IDS[chain];
  if (!goplusChainId) return { checked: false, reason: "not supported for this chain yet" };

  try {
    const url = `https://api.gopluslabs.io/api/v1/token_security/${goplusChainId}?contract_addresses=${tokenAddress}`;
    const { status, body } = await httpGetJson(url);
    if (status !== 200 || !body?.result) return { checked: false, reason: `HTTP ${status}` };

    const data = body.result[tokenAddress.toLowerCase()] || Object.values(body.result)[0];
    if (!data) return { checked: false, reason: "no data returned" };

    const flags = [];
    if (data.is_honeypot === "1") flags.push("🚨 HONEYPOT DETECTED — contract blocks selling");
    const sellTax = parseFloat(data.sell_tax || "0");
    if (sellTax >= 0.15) flags.push(`🚨 Extreme sell tax: ${(sellTax * 100).toFixed(0)}%`);
    if (data.cannot_sell_all === "1") flags.push("🚨 Cannot sell full balance in one transaction");
    if (data.is_mintable === "1") flags.push("⚠️ Mintable — supply can be inflated by owner");
    if (data.hidden_owner === "1") flags.push("⚠️ Hidden owner — contract still controllable despite appearing renounced");
    if (data.is_open_source !== "1") flags.push("⚠️ Contract source not verified");
    const creatorPct = parseFloat(data.creator_percent || "0");
    if (creatorPct > 0.2) flags.push(`⚠️ Creator/deployer holds ${(creatorPct * 100).toFixed(0)}% of supply`);

    return {
      checked: true,
      isHoneypot: data.is_honeypot === "1",
      flags,
      holderCount: parseInt(data.holder_count || "0"),
    };
  } catch (e) {
    return { checked: false, reason: e.message };
  }
}

// ─── Alert ────────────────────────────────────────────────────────────────────
const seenPools = new Set();
const watchlist = new Map(); // poolId -> { pool, safety, firstHolderCount, watchStartedAt, lastRatio }

function riskFlags(p) {
  const flags = [];
  if (p.liquidity < 20000) flags.push("⚠️ Low liquidity — expect high slippage");
  if (p.ageHours < 1) flags.push("⚠️ Extremely new (<1hr) — highest rug risk window");
  if (p.buys1h > 0 && p.sells1h === 0) flags.push("⚠️ Zero sells yet — can't confirm sellability, possible honeypot");
  if (p.fdv > 0 && p.liquidity > 0 && p.fdv / p.liquidity > 100) flags.push("⚠️ FDV/liquidity ratio very high — thin float, easy to manipulate");
  return flags;
}

function buildAlertMessage(p, safety, holderGrowthPct) {
  const flags = riskFlags(p);
  const chainLabel = CHAIN_LABELS[p.chain] || p.chain;

  let safetySection;
  if (safety.checked) {
    const growthLine = holderGrowthPct != null
      ? `📈 Holder count grew +${(holderGrowthPct * 100).toFixed(0)}% since first seen\n`
      : "";
    safetySection = safety.flags.length
      ? `*Contract Safety (GoPlus):*\n${safety.flags.join("\n")}\n${growthLine}\n`
      : `*Contract Safety (GoPlus):* ✅ No red flags detected (${safety.holderCount.toLocaleString()} holders)\n${growthLine}\n`;
  } else if (p.chain === "solana") {
    safetySection = `*Contract Safety:* Not automated for Solana yet — verify manually via RugCheck.xyz before considering.\n\n`;
  } else {
    safetySection = `*Contract Safety:* Check unavailable (${safety.reason}) — verify manually.\n\n`;
  }

  return (
    `🆕🔥 *NEW TOKEN VOLUME SPIKE* 🔥🆕\n\n` +
    `*${p.name}* on ${chainLabel}\n` +
    `\`${p.address}\`\n\n` +
    `*Age:* ${p.ageHours < 1 ? Math.round(p.ageHours * 60) + " min" : p.ageHours.toFixed(1) + "h"}\n` +
    `*Liquidity:* $${p.liquidity.toLocaleString("en-US", { maximumFractionDigits: 0 })}\n` +
    `*24h Volume:* $${p.volume24h.toLocaleString("en-US", { maximumFractionDigits: 0 })} _(${p.ratio.toFixed(1)}x liquidity)_\n` +
    `*1h Volume:* $${p.volume1h.toLocaleString("en-US", { maximumFractionDigits: 0 })}\n` +
    `*FDV:* $${p.fdv.toLocaleString("en-US", { maximumFractionDigits: 0 })}\n` +
    `*Price:* ${p.priceChange1h >= 0 ? "+" : ""}${p.priceChange1h.toFixed(1)}% (1h) / ${p.priceChange24h >= 0 ? "+" : ""}${p.priceChange24h.toFixed(1)}% (24h)\n` +
    `*1h Buys/Sells:* ${p.buys1h} / ${p.sells1h}  _(${p.buySellRatio.toFixed(1)}:1 ratio)_\n\n` +
    (flags.length ? `${flags.join("\n")}\n\n` : "") +
    safetySection +
    `⚠️ *The large majority of brand-new tokens are rug pulls, honeypots, or ` +
    `abandoned within hours. These filters reduce noise and catch SOME scams, ` +
    `not all. Verify liquidity lock and holder concentration yourself before ` +
    `ever considering this. Not financial advice — this is closer to a lottery ` +
    `ticket than a trade.*`
  );
}

async function handleQualifyingPool(p) {
  const safety = await checkTokenSafety(p.address, p.chain);

  if (safety.checked && safety.isHoneypot) {
    await sendTelegram(
      `🚫 *HONEYPOT BLOCKED — NOT ALERTING AS OPPORTUNITY* 🚫\n\n` +
      `*${p.name}* on ${CHAIN_LABELS[p.chain] || p.chain} matched the volume filters, ` +
      `but GoPlus Security confirmed this contract blocks selling.\n\n` +
      `\`${p.address}\`\n\n_This is why the safety check exists. Skipped._`
    );
    return;
  }

  // Solana (or anywhere GoPlus can't check) — can't measure holder growth,
  // so alert immediately on the volume/ratio signal alone.
  if (!safety.checked) {
    await sendTelegram(buildAlertMessage(p, safety, null));
    return;
  }

  // EVM with a successful safety check — hold for holder-growth confirmation
  // instead of alerting on a single snapshot.
  watchlist.set(p.poolId, {
    pool: p, safety, firstHolderCount: safety.holderCount,
    watchStartedAt: Date.now(),
  });
  console.log(`   👀 Watching ${p.name} for holder growth (baseline: ${safety.holderCount} holders)`);
}

async function processWatchlist() {
  if (watchlist.size === 0) return;
  console.log(`\n👀 Re-checking ${watchlist.size} watched token(s) for holder growth...`);

  for (const [poolId, entry] of [...watchlist.entries()]) {
    const fresh = await checkTokenSafety(entry.pool.address, entry.pool.chain);
    await new Promise(r => setTimeout(r, 200));

    if (fresh.checked && fresh.isHoneypot) {
      watchlist.delete(poolId);
      await sendTelegram(
        `🚫 *HONEYPOT DETECTED DURING WATCH PERIOD* 🚫\n\n` +
        `*${entry.pool.name}* went honeypot after initial check — good thing we waited.\n` +
        `\`${entry.pool.address}\``
      );
      continue;
    }
    if (!fresh.checked) continue; // transient API issue, try again next cycle

    const elapsedMin = (Date.now() - entry.watchStartedAt) / 60000;
    const growthPct = entry.firstHolderCount > 0
      ? (fresh.holderCount - entry.firstHolderCount) / entry.firstHolderCount
      : 0;

    if (growthPct >= CONFIG.minHolderGrowthPct) {
      watchlist.delete(poolId);
      await sendTelegram(buildAlertMessage(entry.pool, fresh, growthPct));
      console.log(`   ✅ ${entry.pool.name}: holder growth confirmed (+${(growthPct * 100).toFixed(0)}%), alerted`);
    } else if (elapsedMin > CONFIG.maxWatchMinutes) {
      watchlist.delete(poolId);
      console.log(`   ⌛ ${entry.pool.name}: watch expired without confirmed growth, dropped`);
    }
    // else: keep watching, check again next cycle
  }
}

async function scan() {
  console.log(`\n🔍 Scanning for new pools... ${new Date().toISOString()}`);
  let totalChecked = 0;
  let totalQualified = 0;

  for (const chain of CONFIG.chains) {
    const pools = await fetchNewPools(chain);
    totalChecked += pools.length;
    console.log(`   ${CHAIN_LABELS[chain] || chain}: ${pools.length} new pools fetched`);

    for (const pool of pools) {
      if (seenPools.has(pool.id)) continue;
      seenPools.add(pool.id);

      const evaluated = evaluatePool(pool, chain);
      if (evaluated.passes) {
        console.log(`   🆕 ${evaluated.name}: liquidity $${evaluated.liquidity.toFixed(0)}, vol/liq ${evaluated.ratio.toFixed(1)}x, buy/sell ${evaluated.buySellRatio.toFixed(1)}:1, age ${evaluated.ageHours.toFixed(1)}h`);
        await handleQualifyingPool(evaluated);
        totalQualified++;
        await new Promise(r => setTimeout(r, 500)); // don't burst Telegram/GoPlus
      }
    }
    await new Promise(r => setTimeout(r, 300)); // be polite between chains
  }

  console.log(`   Checked ${totalChecked} pools total, ${totalQualified} qualified (watchlist size: ${watchlist.size})`);

  await processWatchlist();

  // Trim memory
  if (seenPools.size > 20000) {
    const arr = [...seenPools];
    seenPools.clear();
    arr.slice(-10000).forEach(id => seenPools.add(id));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  FEED B — pump.fun new token creation (via PumpPortal, free WebSocket)
// ═══════════════════════════════════════════════════════════════════════════
// Catches Solana tokens at the MOMENT of creation — before they even have a
// DEX pool. Earlier than Feed A can ever be for Solana specifically, but
// also the rawest, least-filtered layer of the entire memecoin pipeline.
let pumpfunWs = null;
let pumpfunReconnectDelay = 5000;

function connectPumpfun() {
  if (!WebSocket) {
    console.warn("⚠️  pump.fun feed disabled — 'ws' package not installed. Run: npm install ws");
    return;
  }
  if (!CONFIG.enablePumpfun) return;

  const url = CONFIG.pumpportalApiKey
    ? `wss://pumpportal.fun/api/data?api-key=${CONFIG.pumpportalApiKey}`
    : `wss://pumpportal.fun/api/data`;

  console.log("🔌 Connecting to pump.fun live feed...");
  pumpfunWs = new WebSocket(url);

  pumpfunWs.on("open", () => {
    console.log("🟢 pump.fun feed connected — subscribing to new token events");
    pumpfunReconnectDelay = 5000; // reset backoff on successful connect
    pumpfunWs.send(JSON.stringify({ method: "subscribeNewToken" }));
  });

  pumpfunWs.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      await handlePumpfunEvent(msg);
    } catch (e) {
      // ignore malformed/non-token messages (subscription confirmations etc)
    }
  });

  pumpfunWs.on("close", () => {
    console.warn(`⚠️  pump.fun feed disconnected — reconnecting in ${pumpfunReconnectDelay / 1000}s`);
    setTimeout(connectPumpfun, pumpfunReconnectDelay);
    pumpfunReconnectDelay = Math.min(pumpfunReconnectDelay * 1.5, 60000); // backoff, cap at 60s
  });

  pumpfunWs.on("error", (e) => {
    console.error("pump.fun feed error:", e.message);
  });
}

async function handlePumpfunEvent(msg) {
  // PumpPortal's new-token event includes fields like: mint, name, symbol,
  // solAmount (initial buy), marketCapSol, uri, traderPublicKey (creator)
  if (!msg.mint || !msg.name) return; // not a token-creation event

  const initialBuySol = parseFloat(msg.solAmount || msg.initialBuy || "0");
  if (initialBuySol < CONFIG.pumpfunMinInitialBuySol) return; // filter tiny/no-conviction launches

  console.log(`🆕 pump.fun: ${msg.name} ($${msg.symbol}) — initial buy ${initialBuySol} SOL`);

  const msgText =
    `🆕🎰 *NEW PUMP.FUN TOKEN* 🎰🆕\n\n` +
    `*${msg.name}* ($${msg.symbol || "?"})\n` +
    `\`${msg.mint}\`\n\n` +
    `*Initial buy:* ${initialBuySol.toFixed(2)} SOL\n` +
    (msg.marketCapSol ? `*Market cap:* ${parseFloat(msg.marketCapSol).toFixed(1)} SOL\n` : "") +
    `*Creator:* \`${msg.traderPublicKey || "unknown"}\`\n\n` +
    `⚠️ *This is the EARLIEST possible stage — pre-liquidity-pool, still on ` +
    `the bonding curve. No safety check is automated for pump.fun tokens. ` +
    `The overwhelming majority of pump.fun launches go to zero within hours. ` +
    `Verify manually via RugCheck.xyz. This is a lottery ticket, not a trade.*`;

  await sendTelegram(msgText);
}

async function testScan() {
  console.log("🧪 Test mode: running one real scan pass immediately...");
  await scan();
  console.log("✅ Test scan complete. If nothing alerted, no pool currently meets the filters — that's normal, not a bug.");
  console.log(`   Note: EVM tokens that qualify go to a holder-growth watchlist (not an`);
  console.log(`   immediate alert) — they'll alert on a LATER scan cycle once growth is`);
  console.log(`   confirmed, or get dropped after ${CONFIG.maxWatchMinutes} min if it never shows up.`);
  console.log(`   Current watchlist size: ${watchlist.size}`);
}

// ─── Start ────────────────────────────────────────────────────────────────────
console.log("═══════════════════════════════════════════════════");
console.log("  New Token Volume Scanner — ⚠️  HIGH RISK ⚠️");
console.log(`  Feed A (GeckoTerminal): ${CONFIG.chains.join(", ")} — every ${CONFIG.pollMs / 60000}min`);
console.log(`  Feed B (pump.fun):      ${CONFIG.enablePumpfun ? (WebSocket ? "✅ live WebSocket" : "❌ 'ws' package missing") : "disabled"}`);
console.log(`  Safety check (GoPlus):  ${Object.keys(GOPLUS_CHAIN_IDS).join(", ")} — Solana not automated`);
console.log(`  Min liquidity: $${CONFIG.minLiquidityUsd.toLocaleString()} | Max age: ${CONFIG.maxAgeHours}h | Min vol/liq: ${CONFIG.minVolLiqRatio}x | Min buy/sell: ${CONFIG.minBuySellRatio}:1`);
console.log(`  Holder growth gate (EVM only): +${(CONFIG.minHolderGrowthPct * 100).toFixed(0)}% within ${CONFIG.maxWatchMinutes}min`);
console.log("═══════════════════════════════════════════════════");
console.log("  Deployed separately from your other scanners on");
console.log("  purpose — use a different bot/chat to keep this");
console.log("  high-risk feed isolated from the rest.");
console.log("═══════════════════════════════════════════════════");

if (process.argv.includes("--test")) {
  testScan();
} else {
  scan();
  setInterval(scan, CONFIG.pollMs);
  connectPumpfun();
}
