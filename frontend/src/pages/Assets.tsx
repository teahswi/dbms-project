import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { Asset } from '../types';
import { SlideOverDrawer } from '../components/SlideOverDrawer';
import {
  Server,
  Plus,
  Upload,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Bug,
  HardDrive,
  Info
} from 'lucide-react';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [csvContent, setCsvContent] = useState('');
  const [importResult, setImportResult] = useState<any>(null);

  // New Asset Form State
  const [newAsset, setNewAsset] = useState({
    hostname: '',
    ip_address: '',
    environment: 'PRODUCTION',
    criticality: 3,
    os_name: 'Linux Ubuntu 22.04 LTS',
    department_id: 1,
    asset_type_id: 1
  });

  const loadAssets = async () => {
    setLoading(true);
    try {
      const res = await api.getAssets({
        search,
        environment: environment || undefined,
        criticality: criticality ? parseInt(criticality) : undefined
      });
      setAssets(res.data || []);
    } catch (err) {
      console.error('Failed to load assets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, [search, environment, criticality]);

  const handleOpenDetail = async (assetId: number) => {
    try {
      const res = await api.getAsset(assetId);
      setSelectedAsset(res.data);
    } catch (err) {
      console.error('Failed to load asset details:', err);
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createAsset(newAsset);
      setShowCreateModal(false);
      loadAssets();
    } catch (err) {
      alert('Error creating asset: ' + err);
    }
  };

  const handleCsvImport = async () => {
    if (!csvContent.trim()) return;
    try {
      const res = await api.bulkImportCsv(csvContent);
      setImportResult(res.data);
      loadAssets();
    } catch (err: any) {
      alert('CSV Import error: ' + err.message);
    }
  };

  const sampleCsv = `hostname,ip_address,criticality,environment,os_name
nx-payment-gateway-99.nexora.corp,10.20.1.99,5,PRODUCTION,Ubuntu 22.04 LTS
nx-k8s-ingress-02.nexora.corp,10.20.2.14,4,PRODUCTION,Ubuntu 22.04 LTS
nx-developer-lap-904.nexora.corp,192.168.1.99,2,STAGING,macOS Sonoma`;

  return (
    <div className="space-y-6">
      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" /> Enterprise Asset & Inventory Management
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            760 Total Managed Assets &bull; Hybrid Multi-Cloud & Corporate Infrastructure
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowImportModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 hover:border-slate-600 text-xs font-medium text-slate-200 transition-colors"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" /> Bulk CSV Ingest
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition-colors shadow-lg shadow-cyan-500/20"
          >
            <Plus className="w-3.5 h-3.5" /> Provision Asset
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="glass-panel rounded-2xl p-4 border border-slate-800 flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[200px] relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search hostname, IP address..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
          />
        </div>

        <select
          value={environment}
          onChange={e => setEnvironment(e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
        >
          <option value="">All Environments</option>
          <option value="PRODUCTION">Production</option>
          <option value="STAGING">Staging</option>
          <option value="DEVELOPMENT">Development</option>
        </select>

        <select
          value={criticality}
          onChange={e => setCriticality(e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
        >
          <option value="">All Criticalities</option>
          <option value="5">Tier 1 - Mission Critical (5)</option>
          <option value="4">Tier 2 - High (4)</option>
          <option value="3">Tier 3 - Medium (3)</option>
          <option value="2">Tier 4 - Low (2)</option>
          <option value="1">Tier 5 - Sandbox (1)</option>
        </select>

        <span className="text-xs font-mono text-slate-400 ml-auto">
          Displaying {assets.length} assets
        </span>
      </div>

      {/* Assets Table */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Hostname</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">OS / Specs</th>
                <th className="py-3 px-4">Department</th>
                <th className="py-3 px-4 text-center">Open Vulns</th>
                <th className="py-3 px-4 text-center">Alerts</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400 font-mono">
                    Loading asset inventory...
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400 font-mono">
                    No matching assets found.
                  </td>
                </tr>
              ) : (
                assets.slice(0, 50).map(asset => {
                  const isCrit = asset.criticality >= 4;
                  return (
                    <tr
                      key={asset.asset_id}
                      className="hover:bg-slate-900/60 transition-colors group cursor-pointer"
                      onClick={() => handleOpenDetail(asset.asset_id)}
                    >
                      <td className="py-3 px-4 font-mono font-medium text-slate-200 group-hover:text-cyan-400 transition-colors">
                        {asset.hostname}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {asset.ip_address}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          asset.environment === 'PRODUCTION'
                            ? 'bg-red-950/40 text-red-400 border-red-800/40'
                            : 'bg-slate-900 text-slate-400 border-slate-800'
                        }`}>
                          {asset.environment}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          asset.criticality === 5
                            ? 'bg-red-950 text-red-400 border-red-700'
                            : (asset.criticality === 4
                            ? 'bg-orange-950 text-orange-400 border-orange-700'
                            : 'bg-slate-900 text-slate-300 border-slate-800')
                        }`}>
                          Tier {asset.criticality}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 truncate max-w-[150px]">
                        {asset.os_name}
                      </td>
                      <td className="py-3 px-4 text-slate-400 truncate max-w-[130px]">
                        {asset.department_name || 'Engineering'}
                      </td>
                      <td className="py-3 px-4 text-center font-mono">
                        {(asset.open_vulns || 0) > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-orange-950/60 text-orange-400 border border-orange-800 font-bold text-[10px]">
                            {asset.open_vulns}
                          </span>
                        ) : (
                          <span className="text-slate-600">0</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center font-mono">
                        {(asset.active_alerts || 0) > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800 font-bold text-[10px]">
                            {asset.active_alerts}
                          </span>
                        ) : (
                          <span className="text-slate-600">0</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenDetail(asset.asset_id);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                        >
                          Inspect &rarr;
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

      {/* Slide-over Detail Drawer */}
      <SlideOverDrawer
        isOpen={!!selectedAsset}
        onClose={() => setSelectedAsset(null)}
        title={selectedAsset?.hostname || 'Asset Detail'}
        subtitle={selectedAsset ? `${selectedAsset.ip_address} • Tier ${selectedAsset.criticality} • ${selectedAsset.environment}` : ''}
        badge={
          selectedAsset?.criticality === 5 ? (
            <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-700 text-xs font-mono font-bold">
              MISSION CRITICAL
            </span>
          ) : null
        }
      >
        {selectedAsset && (
          <div className="space-y-6">
            {/* Exposure Scorecard */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-slate-400">CALCULATED EXPOSURE INDEX</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-2xl font-bold font-mono text-cyan-400">
                    {selectedAsset.exposure_summary?.risk_exposure_index || 0}
                  </span>
                  <span className="text-xs font-mono text-slate-500">/ 100</span>
                </div>
              </div>
              <div className="text-right text-xs font-mono space-y-1">
                <p className="text-slate-400">Open Findings: <span className="text-orange-400 font-bold">{selectedAsset.exposure_summary?.open_vulnerabilities || 0}</span></p>
                <p className="text-slate-400">Active Alerts: <span className="text-red-400 font-bold">{selectedAsset.exposure_summary?.active_alerts || 0}</span></p>
              </div>
            </div>

            {/* Hardware & Spec Cards */}
            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">OPERATING SYSTEM</span>
                <p className="text-slate-200 font-medium">{selectedAsset.os_name}</p>
                <p className="text-slate-400 text-[11px]">{selectedAsset.os_version || '22.04 LTS'}</p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px]">DEPARTMENT & OWNER</span>
                <p className="text-slate-200 font-medium">{selectedAsset.department_name || 'IT Infrastructure'}</p>
                <p className="text-slate-400 text-[11px]">{selectedAsset.owner_name || 'Priya Nair'}</p>
              </div>
            </div>

            {/* Installed Software Inventory with EOL flags */}
            <div className="space-y-3">
              <span className="text-xs font-bold text-white uppercase font-mono tracking-wider flex items-center gap-1.5">
                <HardDrive className="w-4 h-4 text-cyan-400" /> Installed Software Inventory
              </span>
              <div className="divide-y divide-slate-800/80 rounded-xl bg-slate-950/80 border border-slate-800 overflow-hidden">
                {selectedAsset.software_inventory && selectedAsset.software_inventory.length > 0 ? (
                  selectedAsset.software_inventory.map((sw, i) => (
                    <div key={i} className="p-3 flex items-center justify-between text-xs">
                      <div>
                        <p className="font-semibold text-slate-200 font-mono">{sw.software_name}</p>
                        <p className="text-[11px] text-slate-400">{sw.vendor}</p>
                      </div>
                      <div className="text-right">
                        <span className="font-mono text-cyan-400 text-[11px] bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/40">
                          v{sw.version}
                        </span>
                        {sw.is_eol && (
                          <span className="ml-2 px-1.5 py-0.5 rounded bg-red-950 text-red-400 text-[10px] font-mono border border-red-800">
                            EOL Flagged
                          </span>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-4 text-center text-xs text-slate-500 font-mono">
                    No software inventory scanned for this asset.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </SlideOverDrawer>

      {/* CSV Bulk Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-400" /> Ingest Assets via CSV
              </h3>
              <button onClick={() => setShowImportModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Paste CSV records with headers: <code>hostname,ip_address,criticality,environment,os_name</code>
            </p>
            <textarea
              rows={6}
              value={csvContent}
              onChange={e => setCsvContent(e.target.value)}
              placeholder={sampleCsv}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
            {importResult && (
              <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-800 text-xs font-mono text-emerald-400">
                Successfully imported {importResult.imported_count} assets!
              </div>
            )}
            <div className="flex items-center justify-end gap-2.5">
              <button
                onClick={() => setCsvContent(sampleCsv)}
                className="px-3 py-1.5 rounded-xl bg-slate-800 text-xs text-slate-300 font-mono"
              >
                Load Sample
              </button>
              <button
                onClick={handleCsvImport}
                className="px-4 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs"
              >
                Execute Import
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Asset Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <form onSubmit={handleCreateSubmit} className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" /> Provision New Hardware Asset
              </h3>
              <button type="button" onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">HOSTNAME</label>
                <input
                  required
                  type="text"
                  value={newAsset.hostname}
                  onChange={e => setNewAsset({ ...newAsset, hostname: e.target.value })}
                  placeholder="nx-prod-database-01.nexora.corp"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">IP ADDRESS</label>
                  <input
                    required
                    type="text"
                    value={newAsset.ip_address}
                    onChange={e => setNewAsset({ ...newAsset, ip_address: e.target.value })}
                    placeholder="10.20.1.50"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">CRITICALITY TIER</label>
                  <select
                    value={newAsset.criticality}
                    onChange={e => setNewAsset({ ...newAsset, criticality: parseInt(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value={5}>Tier 1 (Mission Critical)</option>
                    <option value={4}>Tier 2 (High)</option>
                    <option value={3}>Tier 3 (Medium)</option>
                    <option value={2}>Tier 4 (Low)</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">OPERATING SYSTEM</label>
                <input
                  type="text"
                  value={newAsset.os_name}
                  onChange={e => setNewAsset({ ...newAsset, os_name: e.target.value })}
                  placeholder="Ubuntu 22.04 LTS"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono"
              >
                Register Asset
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
