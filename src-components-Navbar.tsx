import React from 'react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  realTimeActive: boolean;
  onOpenSettings: () => void;
  onOpenUpdater: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  realTimeActive,
  onOpenSettings,
  onOpenUpdater,
}) => {
  const tabs = [
    { id: 'scanner', label: 'Scanner', icon: '🔍' },
    { id: 'network', label: 'Network Monitor', icon: '🌐' },
    { id: 'realtime', label: 'Real-Time Guard', icon: '⚡' },
    { id: 'analytics', label: 'Analytics', icon: '📊' },
    { id: 'quarantine', label: 'Quarantine Vault', icon: '📦' },
    { id: 'cloud_intel', label: 'Cloud Intel', icon: '☁️' },
    { id: 'ai_threat', label: 'AI Behavioral', icon: '🧠' },
    { id: 'scheduler', label: 'Scheduler', icon: '⏱️' },
    { id: 'database', label: 'Signatures', icon: '🗄️' },
  ];

  return (
    <header className="fixed top-0 left-0 right-0 w-full z-40 bg-[#090d16]/95 backdrop-blur-md border-b border-slate-800/80 px-3 sm:px-6 py-2.5 flex items-center justify-between">
      {/* Brand Logo & Title */}
      <div className="flex items-center space-x-3 shrink-0 mr-2 sm:mr-4">
        <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-400/30 flex items-center justify-center text-sky-400 shadow-[0_0_15px_rgba(56,189,248,0.2)]">
          <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24">
            <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm0 2.18l6 2.25v4.66c0 4.14-2.73 8.01-6 9.07-3.27-1.06-6-4.93-6-9.07V6.43l6-2.25z"/>
          </svg>
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-base font-extrabold tracking-wider text-slate-100 uppercase">
              Automa <span className="text-sky-400">Shield</span>
            </h1>
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-sky-950/80 text-sky-400 border border-sky-800/40">
              v3.8
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">
            Enterprise Endpoint Security
          </p>
        </div>
      </div>

      {/* Center Navigation Tabs */}
      <nav className="flex items-center space-x-1 overflow-x-auto no-scrollbar py-1 px-1 flex-1 min-w-0 max-w-full justify-start lg:justify-center">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all duration-150 shrink-0 ${
                isActive
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-[0_0_12px_rgba(56,189,248,0.15)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span className="text-sm">{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Right Controls */}
      <div className="flex items-center space-x-2 shrink-0 ml-2">
        <div
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border ${
            realTimeActive
              ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
              : 'bg-amber-950/40 text-amber-400 border-amber-800/40'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${realTimeActive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
          <span className="hidden xl:inline">{realTimeActive ? 'Guard Active' : 'Guard Paused'}</span>
        </div>

        <button
          onClick={onOpenUpdater}
          className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700/60 transition"
          title="Update Threat Definitions"
        >
          🔄 <span className="hidden md:inline">Update</span>
        </button>

        <button
          onClick={onOpenSettings}
          className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700/60 transition"
          title="Administrative Settings"
        >
          ⚙️ <span className="hidden md:inline">Settings</span>
        </button>
      </div>
    </header>
  );
};