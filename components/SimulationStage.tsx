import React, { useState, useEffect } from 'react';
import { OwaspItem } from '../types';
import { Lock, Unlock, RefreshCw, AlertTriangle, CheckCircle, Terminal, RotateCcw } from 'lucide-react';

interface Props {
  item: OwaspItem;
}

const SimulationStage: React.FC<Props> = ({ item }) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [activeStep, setActiveStep] = useState(0);
  const [isGlitching, setIsGlitching] = useState(false);
  
  // SQLi State
  const [sqliInput, setSqliInput] = useState('');
  const [sqliSuccess, setSqliSuccess] = useState(false);

  // Access Control State
  const [role, setRole] = useState<'user' | 'admin'>('user');
  
  // Crypto State
  const [plainPassword, setPlainPassword] = useState('SuperSecret123');
  const [storedData, setStoredData] = useState<string>('SuperSecret123');
  const [isEncrypted, setIsEncrypted] = useState(false);

  useEffect(() => {
    resetSimulation();
  }, [item]);

  const resetSimulation = () => {
    setLogs([]);
    setActiveStep(0);
    setSqliInput('');
    setSqliSuccess(false);
    setRole('user');
    setIsEncrypted(false);
    setStoredData('SuperSecret123');
    setIsGlitching(false);
    addLog(`System initialized for ${item.title}...`);
    addLog(`Environment: ${item.simulationType} SANDBOX`);
  };

  const triggerGlitch = () => {
    setIsGlitching(true);
    setTimeout(() => setIsGlitching(false), 500);
  };

  const addLog = (msg: string, type: 'info' | 'error' | 'success' = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [`[${timestamp}] [${type.toUpperCase()}] ${msg}`, ...prev]);
  };

  // --- RENDERERS ---

  const renderSqlInjection = () => {
    const handleExecute = () => {
      if (sqliInput.includes("' OR '1'='1")) {
        setSqliSuccess(true);
        triggerGlitch();
        addLog("MALICIOUS QUERY DETECTED: SELECT * FROM users WHERE user = '' OR '1'='1'", 'error');
        addLog("DUMPING DATABASE...", 'error');
      } else {
        addLog(`Query executed: SELECT * FROM users WHERE user = '${sqliInput}'`, 'info');
        addLog("No results found.", 'info');
      }
    };

    return (
      <div className="space-y-6">
        <div className="bg-slate-900 p-4 rounded border border-slate-700 font-mono text-sm shadow-inner">
          <p className="text-slate-400 mb-2"> Backend Query Logic:</p>
          <code className="text-blue-400 block overflow-x-auto">
            const query = "SELECT * FROM users WHERE name = '" + <span className="text-white">{sqliInput || '{input}'}</span> + "'";
          </code>
        </div>

        <div className="flex space-x-2">
          <input
            type="text"
            value={sqliInput}
            onChange={(e) => setSqliInput(e.target.value)}
            placeholder="Enter username..."
            className="flex-1 bg-slate-800 border border-slate-600 rounded px-4 py-2 text-white focus:ring-2 focus:ring-cyber-accent outline-none transition-shadow"
          />
          <button
            onClick={handleExecute}
            className="bg-cyber-accent hover:bg-cyan-600 text-slate-900 font-bold px-6 py-2 rounded transition-all hover:shadow-[0_0_15px_rgba(6,182,212,0.4)]"
          >
            Execute
          </button>
        </div>
        
        <div className="mt-2">
            <p className="text-sm text-slate-500">Hint: Try <code className="bg-slate-800 px-1 rounded text-orange-400 cursor-pointer hover:bg-slate-700 transition-colors" onClick={() => setSqliInput("' OR '1'='1")}>' OR '1'='1</code></p>
        </div>

        {sqliSuccess && (
          <div className="bg-red-500/20 border border-red-500 p-4 rounded animate-pulse">
            <h3 className="text-red-400 font-bold flex items-center gap-2"><AlertTriangle/> Database Breached!</h3>
            <div className="mt-2 text-xs font-mono text-red-200">
              ID: 1 | User: Admin | Pass: 1234<br/>
              ID: 2 | User: Alice | Pass: abcd<br/>
              ID: 3 | User: Bob | Pass: xyzw
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderAccessControl = () => {
    const handleDelete = (id: number) => {
      if (role === 'admin') {
        addLog(`Deleted User ID ${id}`, 'success');
      } else {
        // Vulnerability Simulation: The button is disabled in UI, but if they could click it...
        // Here we simulate an IDOR request via a specialized button
        addLog(`POST /api/delete/${id} - 403 Forbidden (UI Blocked)`, 'info');
      }
    };

    const simulateIdor = () => {
       triggerGlitch();
       addLog(`ATTACK: Forced POST /api/delete/5 bypassing UI check`, 'error');
       addLog(`Server Check: if (user.role == 'admin') -> FALSE`, 'info');
       addLog(`VULNERABILITY: Server check missing! Deleting record 5...`, 'error');
    };

    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center bg-slate-800 p-4 rounded border border-slate-700">
            <div className="flex items-center gap-3">
                <div className={`p-2 rounded-full transition-colors duration-300 ${role === 'admin' ? 'bg-purple-500 shadow-[0_0_10px_rgba(168,85,247,0.5)]' : 'bg-gray-500'}`}>
                    {role === 'admin' ? <Lock className="w-5 h-5 text-white"/> : <Unlock className="w-5 h-5 text-white"/>}
                </div>
                <div>
                    <p className="font-bold">Current Role: {role.toUpperCase()}</p>
                    <p className="text-xs text-slate-400">Switch roles to test permissions</p>
                </div>
            </div>
            <div className="flex gap-2">
                <button onClick={() => setRole('user')} className={`px-3 py-1 text-sm rounded transition-all ${role === 'user' ? 'bg-slate-600 text-white' : 'bg-slate-800 border border-slate-600 hover:bg-slate-700'}`}>User</button>
                <button onClick={() => setRole('admin')} className={`px-3 py-1 text-sm rounded transition-all ${role === 'admin' ? 'bg-purple-600 text-white shadow-[0_0_10px_rgba(147,51,234,0.3)]' : 'bg-slate-800 border border-slate-600 hover:bg-slate-700'}`}>Admin</button>
            </div>
        </div>

        <div className="border border-slate-700 rounded-lg overflow-hidden">
            <table className="w-full text-left text-sm">
                <thead className="bg-slate-900 text-slate-400">
                    <tr>
                        <th className="p-3">ID</th>
                        <th className="p-3">Data</th>
                        <th className="p-3 text-right">Action</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                    {[1, 2, 3].map(id => (
                        <tr key={id} className="bg-slate-800/50 hover:bg-slate-800 transition-colors">
                            <td className="p-3 font-mono text-slate-500">{id}</td>
                            <td className="p-3">Sensitive Record #{id}</td>
                            <td className="p-3 text-right">
                                <button 
                                    onClick={() => handleDelete(id)}
                                    disabled={role !== 'admin'}
                                    className="text-red-400 hover:text-red-300 disabled:opacity-30 disabled:cursor-not-allowed font-medium transition-opacity"
                                >
                                    Delete
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>

        {role !== 'admin' && (
             <div className="pt-4 border-t border-slate-700 animate-fade-in">
                 <h4 className="text-cyber-warning font-bold text-sm mb-2 flex items-center gap-2"><Terminal className="w-4 h-4"/> Hacker Console</h4>
                 <button onClick={simulateIdor} className="w-full bg-slate-800 border border-cyber-warning/50 text-cyber-warning hover:bg-cyber-warning/10 py-2 rounded text-sm font-mono transition-colors group">
                     <span className="group-hover:translate-x-1 transition-transform inline-block">curl -X POST /api/delete/5</span>
                 </button>
                 <p className="text-xs text-slate-500 mt-2">Simulates sending a direct API request, bypassing the disabled UI button.</p>
             </div>
        )}
      </div>
    );
  };

  const renderCrypto = () => {
    const handleEncrypt = () => {
        setIsEncrypted(!isEncrypted);
        if(!isEncrypted) {
            setStoredData("7f8a9b0c1d2e3f4g5h6i7j8k9l0m");
            addLog("Data encrypted with AES-256 before storage.", "success");
        } else {
            setStoredData("SuperSecret123");
            triggerGlitch();
            addLog("Data stored in PLAIN TEXT. Vulnerable!", "error");
        }
    };

    return (
        <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-800 p-4 rounded border border-slate-700">
                    <h4 className="text-sm font-bold text-slate-400 mb-2">User Input</h4>
                    <div className="flex items-center gap-2 bg-slate-900 p-2 rounded">
                        <span className="font-mono text-white">{plainPassword}</span>
                    </div>
                </div>
                <div className="bg-slate-800 p-4 rounded border border-slate-700 relative overflow-hidden transition-colors duration-500">
                    <h4 className="text-sm font-bold text-slate-400 mb-2">Database Storage</h4>
                    <div className={`flex items-center gap-2 bg-slate-900 p-2 rounded border transition-colors duration-500 ${isEncrypted ? 'border-green-500/50' : 'border-red-500/50'}`}>
                        {isEncrypted ? <Lock className="w-4 h-4 text-green-500 transition-all"/> : <Unlock className="w-4 h-4 text-red-500 transition-all"/>}
                        <span className={`font-mono truncate transition-colors duration-300 ${isEncrypted ? 'text-green-400' : 'text-red-400'}`}>{storedData}</span>
                    </div>
                    {!isEncrypted && (
                         <div className="absolute top-0 right-0 bg-red-600 text-white text-[10px] px-2 py-0.5 font-bold animate-pulse">UNSAFE</div>
                    )}
                </div>
            </div>

            <button 
                onClick={handleEncrypt}
                className={`w-full py-3 rounded font-bold transition-all duration-300 ${isEncrypted ? 'bg-slate-700 text-slate-300' : 'bg-cyber-accent text-slate-900 shadow-[0_0_15px_rgba(6,182,212,0.5)] hover:shadow-[0_0_25px_rgba(6,182,212,0.7)]'}`}
            >
                {isEncrypted ? "Disable Encryption (Simulate Weakness)" : "Enable Encryption"}
            </button>
            
            <div className="bg-slate-900/50 p-4 rounded text-sm text-slate-400 border border-slate-800">
                <p><strong>Scenario:</strong> An attacker dumps the database.</p>
                <p className="mt-2">
                    Result: {isEncrypted ? <span className="text-green-400 font-bold">Attacker sees garbage data. Safe.</span> : <span className="text-red-400 font-bold">Attacker reads "SuperSecret123". Critical Failure.</span>}
                </p>
            </div>
        </div>
    )
  }

  const renderGeneric = () => {
    if (!item.simulationConfig) return null;
    const steps = item.simulationConfig.steps;
    const currentStepData = steps[activeStep];

    const handleAction = () => {
        if (!currentStepData) return;
        addLog(`Action: ${currentStepData.instruction}`);
        if (currentStepData.isMalicious) {
            triggerGlitch();
            addLog(currentStepData.expectedResult, 'error');
        } else {
            addLog(currentStepData.expectedResult, 'success');
        }
        
        if (activeStep < steps.length - 1) {
            setTimeout(() => setActiveStep(prev => prev + 1), 800);
        } else {
            addLog("Scenario Complete.", 'info');
        }
    };

    return (
        <div className="space-y-6">
            <div className="bg-slate-900 p-6 rounded border border-slate-700 text-center relative overflow-hidden">
                 <h3 className="text-xl font-bold text-white mb-2">{item.simulationConfig.scenario}</h3>
                 <p className="text-slate-400 text-sm mb-6">Step {activeStep + 1} of {steps.length}</p>
                 
                 {/* Progress Bar */}
                 <div className="absolute top-0 left-0 h-1 bg-slate-800 w-full">
                    <div className="h-full bg-cyber-accent transition-all duration-500 ease-out" style={{width: `${((activeStep) / steps.length) * 100}%`}}></div>
                 </div>

                 {currentStepData ? (
                     <div className="max-w-md mx-auto animate-slide-up">
                        <p className="mb-6 text-lg">{currentStepData.instruction}</p>
                        <button 
                            onClick={handleAction}
                            className={`px-8 py-3 rounded font-bold shadow-lg transition-all transform active:scale-95 hover:scale-105 ${currentStepData.isMalicious ? 'bg-cyber-danger text-white shadow-cyber-danger/20' : 'bg-cyber-accent text-slate-900 shadow-cyber-accent/20'}`}
                        >
                            {currentStepData.actionLabel}
                        </button>
                     </div>
                 ) : (
                    <div className="animate-fade-in">
                        <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4 animate-bounce"/>
                        <p className="text-green-400 font-bold mb-4">Simulation Finished</p>
                        <button onClick={resetSimulation} className="text-slate-400 hover:text-white flex items-center gap-2 mx-auto transition-colors"><RefreshCw className="w-4 h-4"/> Replay</button>
                    </div>
                 )}
            </div>
        </div>
    );
  };

  return (
    <div className={`grid lg:grid-cols-3 gap-6 h-full transition-transform duration-100 ${isGlitching ? 'animate-glitch' : ''}`}>
      {/* Stage Area */}
      <div className="lg:col-span-2 bg-cyber-800 rounded-xl p-6 shadow-xl border border-cyber-700 flex flex-col transition-colors relative overflow-hidden">
        {/* CRT Scanline Effect */}
        <div className="scanline-overlay"></div>
        <div className="animate-scanline absolute top-0 left-0 w-full h-1 bg-white/5 z-20 pointer-events-none"></div>

        <div className="mb-6 flex items-center justify-between relative z-30">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Terminal className="text-cyber-accent"/> 
                Live Environment
            </h2>
            <div className="flex gap-2">
                <button 
                    onClick={resetSimulation} 
                    className="p-2 hover:bg-slate-700 rounded-full transition-colors text-slate-400 hover:text-white"
                    title="Reset Simulation"
                >
                    <RotateCcw className="w-4 h-4"/>
                </button>
                <span className="text-[10px] font-mono bg-slate-900 px-2 py-1 rounded text-cyber-warning border border-cyber-warning/20 flex items-center">
                    {item.simulationType} MODE
                </span>
            </div>
        </div>
        
        <div className="flex-1 bg-slate-950/50 rounded border border-slate-700/50 p-6 relative overflow-hidden z-30">
            {item.simulationType === 'SQLI' && renderSqlInjection()}
            {item.simulationType === 'ACCESS_CONTROL' && renderAccessControl()}
            {item.simulationType === 'CRYPTO' && renderCrypto()}
            {item.simulationType === 'GENERIC' && renderGeneric()}
        </div>
      </div>

      {/* Terminal/Log Area */}
      <div className="bg-black rounded-xl p-4 font-mono text-xs shadow-xl border border-cyber-700 flex flex-col h-full max-h-[600px] z-30">
        <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-800">
            <span className="text-gray-400">System Logs</span>
            <div className="flex gap-1">
                <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                <div className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" style={{animationDelay: '150ms'}}></div>
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" style={{animationDelay: '300ms'}}></div>
            </div>
        </div>
        <div className="flex-1 overflow-y-auto space-y-2 pr-2 custom-scrollbar">
            {logs.length === 0 && <span className="text-gray-600 italic animate-pulse">Waiting for activity...</span>}
            {logs.map((log, i) => (
                <div key={i} className={`animate-fade-in ${log.includes('[ERROR]') ? 'text-red-400 font-bold' : log.includes('[SUCCESS]') ? 'text-green-400' : 'text-blue-300'}`}>
                    {log}
                </div>
            ))}
        </div>
      </div>
    </div>
  );
};

export default SimulationStage;