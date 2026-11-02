export interface ThreatSignature {
  id: string;
  name: string;
  sha256: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  dateAdded: string;
}

export interface ScanResultItem {
  id: string;
  filePath: string;
  fileName: string;
  sha256: string;
  isThreat: boolean;
  threatName?: string;
  threatType?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
  detectionEngine: 'SIGNATURE' | 'YARA' | 'HEURISTIC' | 'CLOUD_VT' | 'AI_REASONING' | 'CLEAN';
  entropy: number;
  fileSizeBytes: number;
  quarantineId?: string;
  timestamp: string;
}

export interface NetworkConnectionItem {
  id: string;
  pid: number;
  process_name: string;
  executable_path: string;
  local_address: string;
  remote_ip: string;
  remote_port: number;
  remote_hostname?: string;
  protocol: 'TCP' | 'UDP';
  status: 'ACTIVE' | 'BLOCKED' | 'TERMINATED';
  bytes_sent: number;
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
  is_threat: boolean;
  threat_family?: string;
  geo_location?: string;
  reason?: string;
}

export interface QuarantineRecord {
  id: string;
  originalPath: string;
  quarantinePath: string;
  sha256: string;
  threatName: string;
  detectionEngine: string;
  quarantinedAt: string;
  status: 'ISOLATED' | 'RESTORED' | 'PURGED';
  fileSizeBytes: number;
}