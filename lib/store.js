/*
 * store.js — normalized findings database on top of chrome.storage.local.
 *
 * A single record under DB_KEY:
 *   { findings: [ {
 *       id, key, origin, pageUrl, sources:[], snippet, mapsContext,
 *       firstSeen, lastSeen, audits:[ { service, endpoint, httpStatus,
 *                                       apiStatus, classification, detail, ts } ]
 *   } ] }
 *
 * Writes are serialized through a promise chain so concurrent updates from the
 * webRequest listener and content-script messages don't clobber each other.
 */

const DB_KEY = 'gaks_db';
let writeChain = Promise.resolve();

function nowIso() {
  return new Date().toISOString();
}

// A key is logged exactly once, regardless of how many origins/pages it
// appears on — the key string itself is the identity.
export function findingId(key) {
  return key;
}

export async function getDb() {
  const res = await chrome.storage.local.get(DB_KEY);
  const db = res[DB_KEY];
  if (db && Array.isArray(db.findings)) {
    // Always hand back normalized + deduped data, so any duplicates left over
    // from the old key+origin scheme collapse on read.
    return { findings: normalizeFindings(db.findings) };
  }
  return { findings: [] };
}

// Collapse records to one per key, upgrading the legacy single-origin shape
// (origin/pageUrl) to the current arrays and merging everything that shares a key.
function normalizeFindings(findings) {
  const byKey = new Map();
  for (const f of findings) {
    if (!f || !f.key) continue;
    const origins = Array.isArray(f.origins) ? f.origins : (f.origin ? [f.origin] : []);
    const pageUrls = Array.isArray(f.pageUrls) ? f.pageUrls : (f.pageUrl ? [f.pageUrl] : []);
    let rec = byKey.get(f.key);
    if (!rec) {
      rec = {
        id: f.key,
        key: f.key,
        origins: [],
        pageUrls: [],
        sources: [],
        snippet: f.snippet || '',
        mapsContext: !!f.mapsContext,
        firstSeen: f.firstSeen || nowIso(),
        lastSeen: f.lastSeen || nowIso(),
        audits: []
      };
      byKey.set(f.key, rec);
    }
    for (const o of origins) if (rec.origins.indexOf(o) === -1) rec.origins.push(o);
    for (const p of pageUrls) if (rec.pageUrls.indexOf(p) === -1) rec.pageUrls.push(p);
    for (const s of (f.sources || [])) if (rec.sources.indexOf(s) === -1) rec.sources.push(s);
    if (Array.isArray(f.audits) && f.audits.length) rec.audits = rec.audits.concat(f.audits);
    if (f.mapsContext) rec.mapsContext = true;
    if (!rec.snippet && f.snippet) rec.snippet = f.snippet;
    // ISO strings sort lexicographically: keep the earliest first / latest last.
    if (f.firstSeen && f.firstSeen < rec.firstSeen) rec.firstSeen = f.firstSeen;
    if (f.lastSeen && f.lastSeen > rec.lastSeen) rec.lastSeen = f.lastSeen;
  }
  return Array.from(byKey.values());
}

/** Persist the normalized/deduped form once (e.g. on service-worker startup). */
export function migrate() {
  return withDb((db) => {
    db.findings = normalizeFindings(db.findings);
    return db.findings.length;
  });
}

async function setDb(db) {
  await chrome.storage.local.set({ [DB_KEY]: db });
}

// Serialize a read-modify-write against the DB.
function withDb(mutator) {
  writeChain = writeChain.then(async () => {
    const db = await getDb();
    const result = await mutator(db);
    await setDb(db);
    return result;
  }).catch((e) => {
    console.error('[GAKS] store write failed:', e);
  });
  return writeChain;
}

/**
 * Insert or update a finding. `entry` = { key, origin, pageUrl, source,
 * snippet, mapsContext }. A given key is only ever stored once; subsequent
 * sightings merge their origin/source/timestamp into the existing record
 * instead of creating a duplicate. Returns the resulting finding record.
 */
export function upsertFinding(entry) {
  return withDb((db) => {
    const id = findingId(entry.key);
    let rec = db.findings.find((f) => f.id === id);
    const ts = nowIso();
    if (!rec) {
      rec = {
        id,
        key: entry.key,
        origins: [],
        pageUrls: [],
        sources: [],
        snippet: entry.snippet || '',
        mapsContext: !!entry.mapsContext,
        firstSeen: ts,
        lastSeen: ts,
        audits: []
      };
      db.findings.push(rec);
    }
    rec.lastSeen = ts;
    if (entry.origin && rec.origins.indexOf(entry.origin) === -1) rec.origins.push(entry.origin);
    if (entry.pageUrl && rec.pageUrls.indexOf(entry.pageUrl) === -1) rec.pageUrls.push(entry.pageUrl);
    if (entry.snippet && !rec.snippet) rec.snippet = entry.snippet;
    if (entry.mapsContext) rec.mapsContext = true;
    if (entry.source && rec.sources.indexOf(entry.source) === -1) rec.sources.push(entry.source);
    return rec;
  });
}

/** Append an audit result to a finding identified by its id. */
export function addAudit(id, audit) {
  return withDb((db) => {
    const rec = db.findings.find((f) => f.id === id);
    if (!rec) return null;
    audit.ts = audit.ts || nowIso();
    rec.audits.push(audit);
    return rec;
  });
}

/** Replace all audits for a finding (used when re-running a full audit pass). */
export function setAudits(id, audits) {
  return withDb((db) => {
    const rec = db.findings.find((f) => f.id === id);
    if (!rec) return null;
    rec.audits = audits;
    return rec;
  });
}

export function getFinding(id) {
  return getDb().then((db) => db.findings.find((f) => f.id === id) || null);
}

export function deleteFinding(id) {
  return withDb((db) => {
    db.findings = db.findings.filter((f) => f.id !== id);
    return true;
  });
}

export function clearAll() {
  return withDb((db) => {
    db.findings = [];
    return true;
  });
}

/** Merge an imported DB (from JSON) into the current one, deduped by key. */
export function importDb(incoming) {
  return withDb((db) => {
    if (!incoming || !Array.isArray(incoming.findings)) return { merged: 0 };
    const byKey = new Map(db.findings.map((f) => [f.key, f]));
    let merged = 0;
    for (const inc of incoming.findings) {
      if (!inc || !inc.key) continue;
      const existing = byKey.get(inc.key);
      const incOrigins = importedOrigins(inc);
      const incPages = importedPages(inc);
      if (!existing) {
        byKey.set(inc.key, normalizeImported(inc, incOrigins, incPages));
        merged++;
      } else {
        // Same key already known — union everything onto the one record.
        for (const o of incOrigins) if (existing.origins.indexOf(o) === -1) existing.origins.push(o);
        for (const p of incPages) if (existing.pageUrls.indexOf(p) === -1) existing.pageUrls.push(p);
        for (const s of inc.sources || []) if (existing.sources.indexOf(s) === -1) existing.sources.push(s);
        existing.audits = (existing.audits || []).concat(inc.audits || []);
        if (inc.mapsContext) existing.mapsContext = true;
        merged++;
      }
    }
    db.findings = Array.from(byKey.values());
    return { merged };
  });
}

// Accept both the current shape (origins[]) and the legacy single-origin shape.
function importedOrigins(inc) {
  if (Array.isArray(inc.origins)) return inc.origins.slice();
  return inc.origin ? [inc.origin] : [];
}
function importedPages(inc) {
  if (Array.isArray(inc.pageUrls)) return inc.pageUrls.slice();
  return inc.pageUrl ? [inc.pageUrl] : [];
}

function normalizeImported(inc, origins, pages) {
  return {
    id: inc.key,
    key: inc.key,
    origins,
    pageUrls: pages,
    sources: Array.isArray(inc.sources) ? inc.sources.slice() : [],
    snippet: inc.snippet || '',
    mapsContext: !!inc.mapsContext,
    firstSeen: inc.firstSeen || nowIso(),
    lastSeen: inc.lastSeen || nowIso(),
    audits: Array.isArray(inc.audits) ? inc.audits.slice() : []
  };
}
