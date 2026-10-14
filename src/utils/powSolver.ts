// SPDX-License-Identifier: AGPL-3.0-or-later

export interface PowChallenge {
  challengeId: string;
  salt: string;
  difficulty: number;
  sessionToken: string;
}

export interface PowSolution {
  challengeId: string;
  nonce: number;
  sessionToken: string;
}

/**
 * Solves an ephemeral Proof-of-Work challenge using the browser's native Web Crypto API.
 * Finds a nonce such that SHA-256(salt + ':' + nonce) begins with '0' repeated `difficulty` times.
 * Typically finishes in 15-50ms in-browser; negligible for human UX, computationally throttling for bots.
 */
export async function solvePowChallenge(challenge: PowChallenge): Promise<PowSolution> {
  const { challengeId, salt, difficulty, sessionToken } = challenge;
  const targetPrefix = '0'.repeat(difficulty);
  const encoder = new TextEncoder();

  let nonce = 0;
  const maxIterations = 2000000;

  while (nonce < maxIterations) {
    const input = encoder.encode(`${salt}:${nonce}`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', input);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    if (hashHex.startsWith(targetPrefix)) {
      return {
        challengeId,
        nonce,
        sessionToken,
      };
    }
    nonce++;
  }

  return {
    challengeId,
    nonce: -1,
    sessionToken,
  };
}
