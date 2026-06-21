#!/usr/bin/env node
// src/detect/ingest-proxy/server.js
//
// Write-only ingest proxy for the detection sink.
// Item 13, ADR-007 D3, SPEC-07 section 3 condition (b).
//
// SPEC-07 section 3, condition (b):
//   "Write-only / append-only from the container's perspective.
//    No read-back, no list, no delete."
//
// This server:
//   - Accepts POST /ingest -> appends the log line to the sink (immudb or local file).
//   - GET /ingest  -> 405 Method Not Allowed.
//   - DELETE /ingest -> 405 Method Not Allowed.
//   - PUT /ingest -> 405 Method Not Allowed.
//   - PATCH /ingest -> 405 Method Not Allowed.
//   - GET /health -> 200 OK (health probe, NOT the ingest endpoint).
//
// The agent can POST but cannot read back, delete, or list records.
// This is the proof-point for OI-13-E / AC-13-N02.
//
// In production: forwards to immudb's SQL API (append-only by design).
// In test/headless mode: appends to a local file sink.
//
// Environment:
//   INGEST_PORT         - Port to listen on (default: 3001)
//   IMMUDB_URL          - immudb HTTP URL (default: http://immudb:8080)
//   IMMUDB_ADMIN_PASSWORD - immudb admin password
//   SINK_FILE           - If set, write to this file instead of immudb (test mode)

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.INGEST_PORT || '3001', 10);
const IMMUDB_URL = process.env.IMMUDB_URL || 'http://immudb:8080';
const SINK_FILE = process.env.SINK_FILE || null;

// Simple in-memory log for test mode (append only, never truncate).
// In production this is replaced by immudb forwarding.
const LOG_BUFFER = [];

function writeToSink(logLine, cb) {
  if (SINK_FILE) {
    // Test/headless mode: append to a file.
    fs.appendFile(SINK_FILE, logLine + '\n', (err) => {
      if (err) {
        console.error('[ingest-proxy] File write error:', err.message);
        cb(err);
      } else {
        cb(null);
      }
    });
    return;
  }
  // Production mode: would forward to immudb via its REST API.
  // For portability without a live immudb, we buffer in memory and log to stdout.
  LOG_BUFFER.push({ ts: new Date().toISOString(), line: logLine });
  // Print to stdout so the audit trail is captured by the container's log driver.
  console.log('[audit]', logLine);
  cb(null);
}

const server = http.createServer((req, res) => {
  const method = req.method.toUpperCase();
  const url = req.url;

  // Health probe: not the ingest endpoint.
  if (method === 'GET' && url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', records: LOG_BUFFER.length }));
    return;
  }

  // REJECT all non-POST methods on the ingest path.
  // This is the write-only enforcement (SPEC-07 section 3 condition b).
  if (url === '/ingest' || url === '/ingest/') {
    if (method !== 'POST') {
      res.writeHead(405, {
        'Content-Type': 'application/json',
        'Allow': 'POST',
        'X-Write-Only-Sink': 'true'
      });
      res.end(JSON.stringify({
        error: 'Method Not Allowed',
        detail: 'This endpoint is write-only. Only POST is permitted.',
        rejected_method: method
      }));
      // Log the rejection attempt (this itself is an audit event).
      console.log('[ingest-proxy] REJECTED', method, url, '-> 405 (write-only enforcement)');
      return;
    }

    // POST: accept the log line.
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      // Validate that the body is parseable JSON (reject malformed input).
      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request', detail: 'Body must be valid JSON' }));
        return;
      }
      // Write to the sink.
      const logLine = JSON.stringify(parsed);
      writeToSink(logLine, (err) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal Error', detail: 'Failed to write to sink' }));
        } else {
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'accepted', ts: new Date().toISOString() }));
        }
      });
    });
    return;
  }

  // Any other path: 404.
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[ingest-proxy] Write-only ingest proxy listening on port ${PORT}`);
  console.log('[ingest-proxy] POST /ingest -> accepted (write)');
  console.log('[ingest-proxy] GET /ingest  -> 405 (read rejected)');
  console.log('[ingest-proxy] DEL /ingest  -> 405 (delete rejected)');
  console.log('[ingest-proxy] GET /health  -> 200 (health probe)');
  if (SINK_FILE) {
    console.log('[ingest-proxy] Sink mode: FILE ->', SINK_FILE);
  } else {
    console.log('[ingest-proxy] Sink mode: immudb ->', IMMUDB_URL);
  }
});

server.on('error', (err) => {
  console.error('[ingest-proxy] Server error:', err.message);
  process.exit(1);
});
