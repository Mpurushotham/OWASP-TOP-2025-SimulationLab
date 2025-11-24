import React from 'react';
import { OWASP_DATA } from '../constants';
import { ShieldAlert, Terminal, ChevronRight, Trophy, ShieldCheck, Zap, Home } from 'lucide-react';
import { VulnerabilityID } from '../types';

interface SidebarProps {
  currentId: string;
  onSelect: (id: string) => void;
  score: number;
  completedCount: number;
}

const Sidebar: React.FC<SidebarProps> = ({ currentId, onSelect, score, completedCount }) => {
  
  const getRank = (s: number) => {
    if (s === 100) return "CISO";
    if (s >= 80) return "Security Architect";
    if (s >= 50) return "Security Engineer";
    if (s >= 20) return "AppSec Junior";
    return "Script Kiddie";
  }

  // Split data into Top 10 and Bonus
  const top10 = OWASP_DATA.filter(item => !['A11', 'A12'].includes(item.id));
  const bonus = OWASP_DATA.filter(item => ['A11', 'A12'].includes(item.id));

  return (
    <aside className="w-64 bg-cyber-900 border-r border-cyber-700 h-screen overflow-hidden hidden md:flex flex-col sticky top-0 z-20 shadow-2xl">
      <div className="p-6 border-b border-cyber-700 flex items-center space-x-3 bg-cyber-900/95 backdrop-blur shrink-0 cursor-pointer" onClick={() => onSelect('INTRO')}>
        <div className="relative">
          <ShieldAlert className="text-cyber-accent w-8 h-8 relative z-10" />
          <div className="absolute inset-0 bg-cyber-accent/20 blur-lg rounded-full animate-pulse-slow"></div>
        </div>
        <div>
          <h1 className="font-bold text-lg text-white leading-none tracking-tight">OWASP 2025</h1>
          <span className="text-[10px] uppercase tracking-wider text-cyber-accent font-mono">Interactive Lab</span>
        </div>
      </div>

      {/* Security Score Widget */}
      <div className="p-4 border-b border-cyber-700 bg-cyber-800/20 shrink-0">
        <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1">
                <Trophy className="w-3 h-3 text-yellow-500"/> Security Score
            </span>
            <span className="text-sm font-bold text-white">{score}/100</span>
        </div>
        <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden">
            <div 
                className="bg-gradient-to-r from-cyber-danger via-cyber-warning to-cyber-success h-2 rounded-full transition-all duration-1000 ease-out" 
                style={{ width: `${score}%` }}
            ></div>
        </div>
        <div className="flex justify-between items-center text-[10px]">
            <span className="text-slate-500">Rank: <span className="text-cyber-accent font-bold">{getRank(score)}</span></span>
            <span className="text-slate-600">{completedCount}/{OWASP_DATA.length} Fixed</span>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-2 custom-scrollbar">
        {/* Intro Button */}
        <div className="px-4 mb-2 mt-2">
            <button
                onClick={() => onSelect('INTRO')}
                className={`w-full flex items-center space-x-3 px-4 py-2 rounded-lg transition-all duration-300 font-bold text-sm ${
                    currentId === 'INTRO'
                    ? 'bg-cyber-accent text-slate-900 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                    : 'text-slate-400 hover:text-white hover:bg-cyber-800'
                }`}
            >
                <Home className="w-4 h-4"/>
                <span>Mission Brief</span>
            </button>
        </div>

        <div className="px-6 py-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-2">
            Top 10 Vulnerabilities
        </div>
        <ul className="space-y-1 mb-4">
          {top10.map((item) => (
            <li key={item.id}>
              <button
                onClick={() => onSelect(item.id)}
                className={`w-full text-left px-6 py-3.5 flex items-center justify-between group transition-all duration-300 ease-out border-l-4 ${
                  currentId === item.id
                    ? 'bg-cyber-800/80 border-cyber-accent text-white shadow-[inset_0_0_20px_rgba(6,182,212,0.05)]'
                    : 'border-transparent text-slate-400 hover:bg-cyber-800/40 hover:text-slate-200 hover:border-cyber-700 hover:pl-7'
                }`}
              >
                <div className="flex flex-col">
                  <span className={`text-[10px] font-mono font-bold mb-0.5 transition-colors duration-300 ${currentId === item.id ? 'text-cyber-accent' : 'text-slate-600 group-hover:text-slate-500'}`}>
                    {item.id}
                  </span>
                  <span className="text-sm font-medium truncate w-40 transition-transform duration-300 origin-left group-hover:scale-[1.02]">{item.title}</span>
                </div>
                <ChevronRight className={`w-4 h-4 transition-all duration-300 ${currentId === item.id ? 'text-cyber-accent translate-x-0 opacity-100' : 'text-slate-600 -translate-x-2 opacity-0 group-hover:translate-x-0 group-hover:opacity-50'}`} />
              </button>
            </li>
          ))}
        </ul>

        {bonus.length > 0 && (
            <>
                <div className="px-6 py-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest border-t border-cyber-700/50 mt-2">
                    Bonus / Legacy
                </div>
                <ul className="space-y-1">
                    {bonus.map((item) => (
                        <li key={item.id}>
                        <button
                            onClick={() => onSelect(item.id)}
                            className={`w-full text-left px-6 py-3.5 flex items-center justify-between group transition-all duration-300 ease-out border-l-4 ${
                            currentId === item.id
                                ? 'bg-cyber-800/80 border-purple-500 text-white shadow-[inset_0_0_20px_rgba(168,85,247,0.05)]'
                                : 'border-transparent text-slate-400 hover:bg-cyber-800/40 hover:text-slate-200 hover:border-cyber-700 hover:pl-7'
                            }`}
                        >
                            <div className="flex flex-col">
                            <span className={`text-[10px] font-mono font-bold mb-0.5 transition-colors duration-300 ${currentId === item.id ? 'text-purple-400' : 'text-slate-600 group-hover:text-slate-500'}`}>
                                {item.id}
                            </span>
                            <span className="text-sm font-medium truncate w-40 transition-transform duration-300 origin-left group-hover:scale-[1.02]">{item.title}</span>
                            </div>
                            <Zap className={`w-3 h-3 transition-all duration-300 ${currentId === item.id ? 'text-purple-400 opacity-100' : 'text-slate-600 opacity-0 group-hover:opacity-50'}`} />
                        </button>
                        </li>
                    ))}
                </ul>
            </>
        )}
      </nav>
      
      <div className="p-4 border-t border-cyber-700 bg-cyber-900 shrink-0">
        <div className="bg-cyber-800/50 rounded border border-cyber-700 p-3 flex items-center space-x-3 shadow-inner">
          <div className="bg-black/40 p-1.5 rounded relative overflow-hidden">
            <Terminal className="w-4 h-4 text-cyber-warning relative z-10" />
            <div className="absolute inset-0 bg-cyber-warning/20 animate-pulse"></div>
          </div>
          <div className="flex flex-col">
             <span className="text-xs text-slate-300 font-bold">Simulation Active</span>
             <span className="text-[10px] text-cyber-success flex items-center gap-1">
               <span className="w-1.5 h-1.5 bg-cyber-success rounded-full animate-pulse"></span>
               System Online
             </span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;