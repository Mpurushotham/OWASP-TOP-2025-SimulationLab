import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import VulnerabilityDetail from './components/VulnerabilityDetail';
import Introduction from './components/Introduction';
import { OWASP_DATA } from './constants';
import { VulnerabilityID } from './types';

const App: React.FC = () => {
  const [currentId, setCurrentId] = useState<string>('INTRO');
  const [completedItems, setCompletedItems] = useState<Set<string>>(new Set());

  // Restore progress from local storage if desired, keeping simple for now
  
  const activeItem = OWASP_DATA.find(item => item.id === currentId);

  const handleComplete = (id: string) => {
    setCompletedItems(prev => {
      const newSet = new Set(prev);
      newSet.add(id);
      return newSet;
    });
  };

  const score = Math.round((completedItems.size / OWASP_DATA.length) * 100);

  return (
    <div className="flex h-screen bg-cyber-900 text-slate-200 font-sans selection:bg-cyber-accent selection:text-black overflow-hidden">
      <Sidebar 
        currentId={currentId} 
        onSelect={setCurrentId} 
        score={score}
        completedCount={completedItems.size}
      />
      
      <main className="flex-1 flex flex-col h-screen overflow-hidden relative">
        {/* Top decorative bar */}
        <div className="h-1 bg-gradient-to-r from-cyber-accent via-purple-500 to-cyber-danger w-full shrink-0"></div>
        
        {/* Mobile Header */}
        <div className="md:hidden p-4 bg-cyber-800 border-b border-cyber-700 flex justify-between items-center shrink-0">
             <span className="font-bold text-white">OWASP 2025</span>
             <select 
                value={currentId} 
                onChange={(e) => setCurrentId(e.target.value)}
                className="bg-slate-900 text-white text-xs p-2 rounded border border-slate-700"
             >
                 <option value="INTRO">Introduction</option>
                 {OWASP_DATA.map(d => <option key={d.id} value={d.id}>{d.id}</option>)}
             </select>
        </div>

        <div className="flex-1 overflow-hidden p-4 md:p-8 lg:p-12 max-w-7xl mx-auto w-full">
            {currentId === 'INTRO' || !activeItem ? (
                <Introduction onStart={() => setCurrentId(VulnerabilityID.A01)} />
            ) : (
                <VulnerabilityDetail 
                    item={activeItem} 
                    isCompleted={completedItems.has(activeItem.id)}
                    onComplete={() => handleComplete(activeItem.id)}
                />
            )}
        </div>

        {/* Background Grid Effect (CSS only) */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.03]" style={{
            backgroundImage: 'linear-gradient(#334155 1px, transparent 1px), linear-gradient(90deg, #334155 1px, transparent 1px)',
            backgroundSize: '40px 40px'
        }}></div>
      </main>
    </div>
  );
};

export default App;