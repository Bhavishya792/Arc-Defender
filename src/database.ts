/**
 * ARC Defender — Database Layer (In-Memory Datastore)
 *
 * Implements in-memory structured stores for requests, alerts, and ML results
 * with helper methods matching the original SQLite schema and queries.
 */

export interface RequestRecord {
  id: number;
  timestamp: string; // ISO string
  ip: string;
  method: string;
  path: string;
  status_code: number;
  response_time_ms: number;
  user_agent: string;
  referer: string;
  request_size: number;
  response_size: number;
  country: string | null;
  region: string | null;
  city: string | null;
  is_login_attempt: number;
  login_success: number;
}

export interface AlertRecord {
  id: number;
  timestamp: string; // ISO string
  alert_type: string;
  severity: string;
  ip: string | null;
  description: string;
  source: string;
  stats: string | null;
  risk_score: number | null;
  acknowledged?: boolean;
}

export interface MlResultRecord {
  id: number;
  timestamp: string;
  ip: string;
  anomaly_score: number;
  is_anomaly: number;
  features: string; // JSON string
}

class ArcDatabase {
  private requests: RequestRecord[] = [];
  private alerts: AlertRecord[] = [];
  private mlResults: MlResultRecord[] = [];
  private nextRequestId = 1;
  private nextAlertId = 1;
  private nextMlResultId = 1;

  public syncMode = false;

  public insertRequest(data: Partial<RequestRecord>): RequestRecord {
    const record: RequestRecord = {
      id: this.nextRequestId++,
      timestamp: data.timestamp || new Date().toISOString(),
      ip: data.ip || "127.0.0.1",
      method: (data.method || "GET").toUpperCase(),
      path: data.path || "/",
      status_code: data.status_code || 200,
      response_time_ms: data.response_time_ms !== undefined ? data.response_time_ms : 10,
      user_agent: data.user_agent || "",
      referer: data.referer || "",
      request_size: data.request_size || 0,
      response_size: data.response_size || 0,
      country: data.country || null,
      region: data.region || null,
      city: data.city || null,
      is_login_attempt: data.is_login_attempt ? 1 : 0,
      login_success: data.login_success ? 1 : 0,
    };
    this.requests.push(record);
    return record;
  }

  public insertAlert(data: Partial<AlertRecord>): AlertRecord {
    const record: AlertRecord = {
      id: this.nextAlertId++,
      timestamp: data.timestamp || new Date().toISOString(),
      alert_type: data.alert_type || "generic",
      severity: data.severity || "medium",
      ip: data.ip || null,
      description: data.description || "",
      source: data.source || "rule",
      stats: data.stats || null,
      risk_score: data.risk_score !== undefined ? data.risk_score : null,
      acknowledged: data.acknowledged !== undefined ? data.acknowledged : false,
    };
    this.alerts.push(record);
    return record;
  }

  public acknowledgeAlert(id: number): boolean {
    const alert = this.alerts.find((a) => a.id === id);
    if (!alert) return false;
    alert.acknowledged = true;
    return true;
  }

  public acknowledgeAllAlerts(): number {
    let count = 0;
    for (const a of this.alerts) {
      if (!a.acknowledged) {
        a.acknowledged = true;
        count++;
      }
    }
    return count;
  }

  public clearAlerts(): void {
    this.alerts = [];
  }

  public insertMlResult(data: Partial<MlResultRecord>): MlResultRecord {
    const record: MlResultRecord = {
      id: this.nextMlResultId++,
      timestamp: data.timestamp || new Date().toISOString(),
      ip: data.ip || "unknown",
      anomaly_score: data.anomaly_score !== undefined ? data.anomaly_score : 0,
      is_anomaly: data.is_anomaly ? 1 : 0,
      features: data.features || "{}",
    };
    this.mlResults.push(record);
    return record;
  }

  public getAllRequests(): RequestRecord[] {
    return this.requests;
  }

  public getAllAlerts(): AlertRecord[] {
    return this.alerts;
  }

  public getAllMlResults(): MlResultRecord[] {
    return this.mlResults;
  }

  public getRequestsSince(cutoffIso: string): RequestRecord[] {
    return this.requests.filter((r) => r.timestamp >= cutoffIso);
  }

  public getAlertsSince(cutoffIso: string): AlertRecord[] {
    return this.alerts.filter((a) => a.timestamp >= cutoffIso);
  }

  public getMlResultsSince(cutoffIso: string): MlResultRecord[] {
    return this.mlResults.filter((m) => m.timestamp >= cutoffIso);
  }

  public getRequestById(id: number): RequestRecord | null {
    return this.requests.find((r) => r.id === id) || null;
  }

  public clearAll(): void {
    this.requests = [];
    this.alerts = [];
    this.mlResults = [];
    this.nextRequestId = 1;
    this.nextAlertId = 1;
    this.nextMlResultId = 1;
  }
}

export const db = new ArcDatabase();
