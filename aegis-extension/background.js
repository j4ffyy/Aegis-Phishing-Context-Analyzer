/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Background Service Worker (Stub)
 * 
 * Specification: Implementation Plan §5.1, Milestone 2.3
 * 
 * Manages asynchronous API dispatch, Chrome storage synchronization,
 * and service health monitoring with a 2.0s abort timeout.
 * 
 * TODO(Milestone 2.3): Implement message passing router:
 * - chrome.runtime.onMessage listener
 * - AbortController timeout on backend fetch()
 * - Offline fallback delegation to Local Heuristics
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("[Aegis] Background service worker initialized (DEV STUB).");
});
