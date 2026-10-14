// SPDX-License-Identifier: AGPL-3.0-or-later

export interface EngineProfile {
  id: string;
  label: string;
  description: string;
  defaultOutputName: string;
}

export interface OutputFileArtifact {
  name: string;
  size: number;
  lines: number;
  sha256: string;
  mimeType: string;
  content: string;
  downloadUrl: string;
}

export interface ExecutionResult {
  runId: string;
  success: boolean;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  pipelineProfile?: string;
  htmlSha256: string;
  jsSha256: string;
  stdout: string;
  stderr: string;
  outputFile: OutputFileArtifact | null;
  timestamp: number;
}

export interface SystemStatus {
  runtime: string;
  activeCachedArtifacts: number;
  nodeVersion: string;
  platform: string;
  arch: string;
  systemUptime: number;
}
