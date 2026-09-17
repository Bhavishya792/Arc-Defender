/**
 * ARC Defender — Analytics Module
 */

import { db, RequestRecord } from "./database.js";

export function getCutoff(hours: number): string {
  const d = new Date(Date.now() - hours * 3600 * 1000);
  return d.toISOString();
}

export function getOverviewStats(hours = 24) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);
  const alerts = db.getAlertsSince(cutoff);

  const total_requests = reqs.length;
  const unique_ips = new Set(reqs.map((r) => r.ip));
  const unique_clients = unique_ips.size;

  let total_time = 0;
  let total_errors = 0;
  for (const r of reqs) {
    total_time += r.response_time_ms || 0;
    if (r.status_code >= 400) {
      total_errors++;
    }
  }

  const avg_response_time = total_requests > 0 ? total_time / total_requests : 0.0;
  const alert_count = alerts.length;

  return {
    total_requests,
    unique_clients,
    avg_response_time,
    total_errors,
    alert_count,
  };
}

export function getRequestsOverTime(hours = 24, bucket_minutes = 15) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  // Group by bucket timestamp
  const bucketMs = bucket_minutes * 60 * 1000;
  const buckets = new Map<string, { count: number; errors: number; total_latency: number }>();

  // Sort chronologically
  const sorted = [...reqs].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  for (const r of sorted) {
    const time = new Date(r.timestamp).getTime();
    const bucketTime = Math.floor(time / bucketMs) * bucketMs;
    const bucketIso = new Date(bucketTime).toISOString().replace(/\.\d{3}Z$/, ":00Z");
    const item = buckets.get(bucketIso) || { count: 0, errors: 0, total_latency: 0 };
    item.count++;
    if (r.status_code >= 400) item.errors++;
    item.total_latency += r.response_time_ms || 0;
    buckets.set(bucketIso, item);
  }

  const result: { bucket: string; count: number; errors: number; avg_latency: number }[] = [];
  for (const [bucket, data] of buckets.entries()) {
    result.push({
      bucket,
      count: data.count,
      errors: data.errors,
      avg_latency: data.count > 0 ? Math.round((data.total_latency / data.count) * 10) / 10 : 0,
    });
  }

  result.sort((a, b) => a.bucket.localeCompare(b.bucket));
  return result;
}

export function getRequestsByEndpoint(hours = 24, limit = 10) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  const map = new Map<string, { count: number; total_time: number; errors: number }>();
  for (const r of reqs) {
    const entry = map.get(r.path) || { count: 0, total_time: 0, errors: 0 };
    entry.count++;
    entry.total_time += r.response_time_ms || 0;
    if (r.status_code >= 400) entry.errors++;
    map.set(r.path, entry);
  }

  const list = Array.from(map.entries()).map(([path, val]) => ({
    path,
    count: val.count,
    avg_response_time: val.count > 0 ? val.total_time / val.count : 0,
    error_rate: val.count > 0 ? val.errors / val.count : 0,
  }));

  list.sort((a, b) => b.count - a.count);
  return list.slice(0, limit);
}

export function getRequestsByMethod(hours = 24) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  const map = new Map<string, number>();
  for (const r of reqs) {
    map.set(r.method, (map.get(r.method) || 0) + 1);
  }

  const list = Array.from(map.entries()).map(([method, count]) => ({ method, count }));
  list.sort((a, b) => b.count - a.count);
  return list;
}

export function getRequestsByStatus(hours = 24) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  const map = new Map<number, number>();
  for (const r of reqs) {
    map.set(r.status_code, (map.get(r.status_code) || 0) + 1);
  }

  const list = Array.from(map.entries()).map(([status_code, count]) => ({ status_code, count }));
  list.sort((a, b) => a.status_code - b.status_code);
  return list;
}

export function getTopClients(hours = 24, limit = 10) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  const map = new Map<
    string,
    { count: number; last_seen: string; user_agent: string; country: string | null }
  >();

  for (const r of reqs) {
    const prev = map.get(r.ip);
    if (!prev) {
      map.set(r.ip, {
        count: 1,
        last_seen: r.timestamp,
        user_agent: r.user_agent,
        country: r.country,
      });
    } else {
      prev.count++;
      if (r.timestamp > prev.last_seen) {
        prev.last_seen = r.timestamp;
        prev.user_agent = r.user_agent;
        prev.country = r.country;
      }
    }
  }

  const list = Array.from(map.entries()).map(([ip, val]) => ({
    ip,
    count: val.count,
    last_seen: val.last_seen,
    user_agent: val.user_agent,
    country: val.country,
  }));

  list.sort((a, b) => b.count - a.count);
  return list.slice(0, limit);
}

export interface RequestFilterParams {
  hours?: number;
  limit?: number;
  offset?: number;
  search?: string;
  method?: string;
  status_group?: string; // "2xx" | "3xx" | "4xx" | "5xx"
  status_code?: number;
  ip?: string;
  min_latency?: number;
  errors_only?: boolean;
}

export function getRecentRequests(options: RequestFilterParams | number = 24, limitArg = 50) {
  let hours = 24;
  let limit = limitArg;
  let offset = 0;
  let search: string | undefined;
  let method: string | undefined;
  let status_group: string | undefined;
  let status_code: number | undefined;
  let ip: string | undefined;
  let min_latency: number | undefined;
  let errors_only = false;

  if (typeof options === "number") {
    hours = options;
  } else if (options && typeof options === "object") {
    hours = options.hours || 24;
    limit = options.limit !== undefined ? options.limit : 50;
    offset = options.offset || 0;
    search = options.search?.trim();
    method = options.method?.trim();
    status_group = options.status_group?.trim();
    status_code = options.status_code;
    ip = options.ip?.trim();
    min_latency = options.min_latency;
    errors_only = !!options.errors_only;
  }

  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);
  const total = reqs.length;

  let filteredReqs = reqs;

  if (search) {
    const q = search.toLowerCase();
    filteredReqs = filteredReqs.filter(
      (r) =>
        r.path.toLowerCase().includes(q) ||
        r.ip.toLowerCase().includes(q) ||
        r.user_agent.toLowerCase().includes(q) ||
        r.method.toLowerCase().includes(q)
    );
  }

  if (method && method !== "ALL") {
    filteredReqs = filteredReqs.filter((r) => r.method.toUpperCase() === method.toUpperCase());
  }

  if (ip) {
    filteredReqs = filteredReqs.filter((r) => r.ip.toLowerCase().includes(ip.toLowerCase()));
  }

  if (status_code) {
    filteredReqs = filteredReqs.filter((r) => r.status_code === status_code);
  } else if (status_group && status_group !== "ALL") {
    if (status_group === "2xx") {
      filteredReqs = filteredReqs.filter((r) => r.status_code >= 200 && r.status_code < 300);
    } else if (status_group === "3xx") {
      filteredReqs = filteredReqs.filter((r) => r.status_code >= 300 && r.status_code < 400);
    } else if (status_group === "4xx") {
      filteredReqs = filteredReqs.filter((r) => r.status_code >= 400 && r.status_code < 500);
    } else if (status_group === "5xx") {
      filteredReqs = filteredReqs.filter((r) => r.status_code >= 500 && r.status_code < 600);
    }
  }

  if (errors_only) {
    filteredReqs = filteredReqs.filter((r) => r.status_code >= 400);
  }

  if (min_latency !== undefined && min_latency > 0) {
    filteredReqs = filteredReqs.filter((r) => r.response_time_ms >= min_latency);
  }

  const filteredTotal = filteredReqs.length;
  const sorted = [...filteredReqs].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const paged = sorted.slice(offset, offset + limit).map((r) => ({
    id: r.id,
    timestamp: r.timestamp,
    ip: r.ip,
    method: r.method,
    path: r.path,
    status_code: r.status_code,
    response_time_ms: r.response_time_ms,
    user_agent: r.user_agent,
  }));

  return {
    total,
    filtered: filteredTotal,
    requests: paged,
  };
}

export function getRequestDetail(requestId: number) {
  return db.getRequestById(requestId);
}

export function getErrorStats(hours = 24) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  let four_xx_count = 0;
  let five_xx_count = 0;
  const commonMap = new Map<number, number>();
  const trendMap = new Map<string, number>();

  for (const r of reqs) {
    if (r.status_code >= 400 && r.status_code < 500) {
      four_xx_count++;
      commonMap.set(r.status_code, (commonMap.get(r.status_code) || 0) + 1);
    } else if (r.status_code >= 500 && r.status_code < 600) {
      five_xx_count++;
      commonMap.set(r.status_code, (commonMap.get(r.status_code) || 0) + 1);
    }

    if (r.status_code >= 400) {
      const time = new Date(r.timestamp).getTime();
      const hourMs = 60 * 60 * 1000;
      const bucketTime = Math.floor(time / hourMs) * hourMs;
      const bucketIso = new Date(bucketTime).toISOString().replace(/\.\d{3}Z$/, ":00Z");
      trendMap.set(bucketIso, (trendMap.get(bucketIso) || 0) + 1);
    }
  }

  const common_errors = Array.from(commonMap.entries())
    .map(([status_code, count]) => ({ status_code, count }))
    .sort((a, b) => b.count - a.count);

  const error_trends = Array.from(trendMap.entries())
    .map(([bucket, count]) => ({ bucket, count }))
    .sort((a, b) => a.bucket.localeCompare(b.bucket));

  return {
    four_xx_count,
    five_xx_count,
    error_trends,
    common_errors,
  };
}

export function getLatencyStats(hours = 24) {
  const cutoff = getCutoff(hours);
  const reqs = db.getRequestsSince(cutoff);

  const times = reqs
    .map((r) => r.response_time_ms)
    .filter((t) => t !== null && t !== undefined)
    .sort((a, b) => a - b);

  const count = times.length;
  if (count === 0) {
    return {
      avg: 0,
      p50: 0,
      p95: 0,
      p99: 0,
      max: 0,
      distribution: [],
    };
  }

  function getPercentile(data: number[], p: number): number {
    if (!data.length) return 0;
    const k = (data.length - 1) * p;
    const f = Math.floor(k);
    const c = Math.ceil(k);
    if (f === c) return data[f];
    return data[f] * (c - k) + data[c] * (k - f);
  }

  const avg = times.reduce((a, b) => a + b, 0) / count;
  const p50 = getPercentile(times, 0.5);
  const p95 = getPercentile(times, 0.95);
  const p99 = getPercentile(times, 0.99);
  const max = times[times.length - 1];

  const buckets = {
    "<10ms": 0,
    "<50ms": 0,
    "<100ms": 0,
    "<500ms": 0,
    "<1000ms": 0,
    ">=1000ms": 0,
  };

  for (const t of times) {
    if (t < 10) buckets["<10ms"]++;
    else if (t < 50) buckets["<50ms"]++;
    else if (t < 100) buckets["<100ms"]++;
    else if (t < 500) buckets["<500ms"]++;
    else if (t < 1000) buckets["<1000ms"]++;
    else buckets[">=1000ms"]++;
  }

  const distribution = Object.entries(buckets).map(([bucket_label, c]) => ({
    bucket_label,
    count: c,
  }));

  return {
    avg,
    p50,
    p95,
    p99,
    max,
    distribution,
  };
}

export function getClientDetail(ip: string) {
  const reqs = db.getAllRequests().filter((r) => r.ip === ip);
  if (reqs.length === 0) return null;

  let total_time = 0;
  let min_ts = reqs[0].timestamp;
  let max_ts = reqs[0].timestamp;

  const uaMap = new Map<string, number>();
  const pathMap = new Map<string, number>();
  const methodMap = new Map<string, number>();
  const statusMap = new Map<number, number>();

  let country: string | null = null;
  let region: string | null = null;
  let city: string | null = null;

  for (const r of reqs) {
    total_time += r.response_time_ms || 0;
    if (r.timestamp < min_ts) min_ts = r.timestamp;
    if (r.timestamp > max_ts) max_ts = r.timestamp;

    uaMap.set(r.user_agent, (uaMap.get(r.user_agent) || 0) + 1);
    pathMap.set(r.path, (pathMap.get(r.path) || 0) + 1);
    methodMap.set(r.method, (methodMap.get(r.method) || 0) + 1);
    statusMap.set(r.status_code, (statusMap.get(r.status_code) || 0) + 1);

    if (r.country) country = r.country;
    if (r.region) region = r.region;
    if (r.city) city = r.city;
  }

  const user_agents = Array.from(uaMap.entries())
    .map(([user_agent, count]) => ({ user_agent, count }))
    .sort((a, b) => b.count - a.count);

  const endpoints_hit = Array.from(pathMap.entries())
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count);

  const methods = Array.from(methodMap.entries()).map(([method, count]) => ({ method, count }));
  const status_codes = Array.from(statusMap.entries()).map(([status_code, count]) => ({
    status_code,
    count,
  }));

  return {
    ip,
    request_count: reqs.length,
    last_seen: max_ts,
    first_seen: min_ts,
    avg_response_time: total_time / reqs.length,
    country,
    region,
    city,
    user_agents,
    endpoints_hit,
    methods,
    status_codes,
  };
}
