/*
 * ignore.js — domains whose pages we skip entirely (module world).
 *
 * Matching is on the *visited page's* host, not the resource host: if you are
 * browsing google.com we skip it, but a key that example.com loads from
 * maps.googleapis.com is still detected.
 *
 * The content-script world keeps its own copy of this list/matcher in
 * content/patterns.js (content scripts can't import modules) — keep them in sync.
 */

// Any google.<tld> / *.google.<tld> (google.com, google.co.uk, maps.google.de…).
export const GOOGLE_HOST_RE = /(^|\.)google\.[a-z]{2,}(\.[a-z]{2,})?$/;

export const DEFAULT_IGNORED_DOMAINS = [
  // Google-owned services & infrastructure
  'gstatic.com', 'googleusercontent.com', 'googleapis.com', 'googlevideo.com',
  'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com',
  'googleadservices.com', 'doubleclick.net', 'withgoogle.com', 'googlesource.com',
  'goo.gl', 'gmail.com', 'youtube.com', 'youtu.be', 'ytimg.com', 'ggpht.com',
  'android.com', 'chromium.org',
  // Other large first-party noise sources
  'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
  'yahoo.com', 'yahooapis.com', 'yimg.com'
];

export function hostIsIgnored(host, extra) {
  if (!host) return false;
  host = String(host).toLowerCase();
  if (GOOGLE_HOST_RE.test(host)) return true;
  const list = DEFAULT_IGNORED_DOMAINS.concat(Array.isArray(extra) ? extra : []);
  return list.some((d) => d && (host === d || host.endsWith('.' + d)));
}

export function urlHostIsIgnored(url, extra) {
  try { return hostIsIgnored(new URL(url).hostname, extra); } catch (e) { return false; }
}
