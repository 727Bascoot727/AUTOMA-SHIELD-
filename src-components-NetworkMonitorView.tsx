import React, { useState } from 'react';
import { NetworkConnectionItem } from '../types/antivirus';

interface NetworkMonitorViewProps {
  connections: NetworkConnectionItem[];
  onBlockConnection: (id: string, remoteIp: string, pid: number, processName: string) => void;
  onUnblockConnection: (id: string, remoteIp: string) => void;
  onKillProcess: (pid: number) => void;
  onRefresh: () => void;
}

export const NetworkMonitorView: React.FC<NetworkMonitorViewProps> = ({
  connections,
  onBlockConnection,
  onUnblockConnection,
  onKillProcess,
  onRefresh,
}) => {
  const [filter, setFilter] = useState<'ALL' | 'THREATS' | 'BLOCKED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredConnections = connections.filter((conn) => {
    if (filter === 'THREATS' && !conn.is_threat) return false;
    if (filter === 'BLOCKED' && conn.status !== 'BLOCKED') return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        conn.process_name.toLowerCase().includes(term) ||
        conn.remote_ip.toLowerCase().includes(term) ||
        (conn.threat_family && conn.threat_family.toLowerCase().includes(term))
      );
    }
    return true;
  });

  const threatCount = connections.filter((c) => c.is_threat).length;
  const blockedCount = connections.filter((c) => c.status === 'BLOCKED').length;

  return (
    <div className="space-y-6">
      {/* Top Banner & Stats */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xl">🌐</span>
            <h2 className="text-lg font-bold text-slate-100">Active Process Network & Outbound Monitor</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time socket inspection correlated with background scanner heuristics. Block malicious C2 beacons instantly.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="bg-slate-800/80 border border-slate-700/60 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Active Sockets</span>
            <span className="text-base font-extrabold text-sky-400">{connections.length}</span>
          </div>
          <div className="bg-rose-950/40 border border-rose-800/40 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[10px] uppercase font-bold text-rose-300 block">Flagged Threats</span>
            <span className="text-base font-extrabold text-rose-400">{threatCount}</span>
          </div>
          <div className="bg-amber-950/40 border border-amber-800/40 rounded-lg px-3 py-1.5 text-center">
            <span className="text-[10px] uppercase font-bold text-amber-300 block">Blocked</span>
            <span className="text-base font-extrabold text-amber-400">{blockedCount}</span>
          </div>
          <button
            onClick={onRefresh}
            className="px-3 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold shadow transition"
          >
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filter === 'ALL' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40' : 'bg-slate-800/60 text-slate-400 hover:bg-slate-800'
            }`}
          >
            All Connections ({connections.length})
          </button>
          <button
            onClick={() => setFilter('THREATS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filter === 'THREATS' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-slate-800/60 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Hostile / Suspicious ({threatCount})
          </button>
          <button
            onClick={() => setFilter('BLOCKED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filter === 'BLOCKED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-slate-800/60 text-slate-400 hover:bg-slate-800'
            }`}
          >
            Blocked Sockets ({blockedCount})
          </button>
        </div>

        <input
          type="text"
          placeholder="Filter by process, IP, or threat..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full sm:w-72 bg-slate-900/80 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
        />
      </div>

      {/* Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Process / PID</th>
                <th className="py-3 px-4">Remote Destination</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Threat Assessment</th>
                <th className="py-3 px-4 text-right">Defensive Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredConnections.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No matching active socket connections found.
                  </td>
                </tr>
              ) : (
                filteredConnections.map((conn) => {
                  const isBlocked = conn.status === 'BLOCKED';
                  return (
                    <tr
                      key={conn.id}
                      className={`hover:bg-slate-800/40 transition ${
                        conn.is_threat ? 'bg-rose-950/15' : ''
                      }`}
                    >
                      <td className="py-3 px-4">
                        {isBlocked ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/60 text-amber-400 border border-amber-800/60">
                            🚫 BLOCKED
                          </span>
                        ) : conn.is_threat ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60 animate-pulse">
                            🚨 SUSPICIOUS
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                            ✅ ACTIVE
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">{conn.process_name}</div>
                        <div className="text-[10px] text-slate-400 font-mono">PID: {conn.pid}</div>
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <div className="text-slate-200">
                          {conn.remote_ip}:{conn.remote_port}
                        </div>
                        {conn.remote_hostname && (
                          <div className="text-[10px] text-sky-400">{conn.remote_hostname}</div>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">{conn.protocol}</td>
                      <td className="py-3 px-4">
                        {conn.is_threat ? (
                          <div>
                            <span className="font-bold text-rose-400">{conn.threat_family || 'Hostile Connection'}</span>
                            {conn.reason && (
                              <div className="text-[10px] text-slate-400 mt-0.5">{conn.reason}</div>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400">Verified System Traffic</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right space-x-1.5">
                        {isBlocked ? (
                          <button
                            onClick={() => onUnblockConnection(conn.id, conn.remote_ip)}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-[11px] font-medium transition"
                          >
                            Unblock
                          </button>
                        ) : (
                          <button
                            onClick={() => onBlockConnection(conn.id, conn.remote_ip, conn.pid, conn.process_name)}
                            className="px-2.5 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded text-[11px] font-medium shadow transition"
                          >
                            Block Socket
                          </button>
                        )}
                        <button
                          onClick={() => onKillProcess(conn.pid)}
                          className="px-2.5 py-1 bg-rose-700 hover:bg-rose-600 text-white rounded text-[11px] font-medium shadow transition"
                        >
                          Kill Process
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};