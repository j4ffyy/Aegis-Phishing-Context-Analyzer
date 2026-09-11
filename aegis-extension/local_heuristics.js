/**
 * Aegis: AI-Powered Phishing Context Analyzer
 * Component: Local Heuristics Scoring Engine (Stub)
 * 
 * Specification: Implementation Plan §6.2, Milestone 2.2
 * 
 * Evaluates rule-based phishing indicators client-side for immediate
 * display and offline resilience if the backend is unreachable.
 * 
 * TODO(Milestone 2.2): Implement rule evaluation:
 * - Urgent call-to-action keyword density
 * - Display name vs reply-to mismatch
 * - Free email provider impersonation
 * - Link count & deceptive anchor text
 */

window.AegisLocalHeuristics = {
  evaluate(emailData) {
    // Milestone 1 stub: returns baseline neutral score
    return {
      score: 15,
      flags: []
    };
  }
};
