import React from 'react';
import { Shield, Terminal, Zap, GitBranch, Lock, Brain, PlayCircle, Award, MousePointer2 } from 'lucide-react';

interface Props {
  onStart: () => void;
}

const Introduction: React.FC<Props> = ({ onStart }) => {
  return (
    <div className="h-full overflow-y-auto custom-scrollbar p-6 md:p-12 animate-fade-in text-slate-200">
      
      {/* Hero Section */}
      <div className="max-w-4xl mx-auto text-center mb-16 relative">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-32 bg-cyber-accent/20 blur-3xl rounded-full"></div>
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-800 border border-cyber-700 text-cyber-accent text-xs font-mono mb-6 animate-slide-up">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
            SYSTEM ONLINE: OWASP PROTOCOL 2025
        </div>
        
        <h1 className="text-5xl md:text-7xl font-bold text-white mb-6 tracking-tight animate-slide-up animate-delay-100">
          SECURE THE <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-accent to-blue-500">FUTURE</span>
        </h1>
        
        <p className="text-lg text-slate-400 mb-8 max-w-2xl mx-auto leading-relaxed animate-slide-up animate-delay-200">
          Welcome to the interactive cyber defense lab. Master the <strong>OWASP Top 10 2025</strong> through real-world attack simulations, automated pipeline visualizations, and AI-powered remediation.
        </p>

        <button 
            onClick={onStart}
            className="group relative inline-flex items-center gap-3 bg-cyber-accent hover:bg-cyan-400 text-slate-900 px-8 py-4 rounded-lg font-bold text-lg transition-all duration-300 shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_30px_rgba(6,182,212,0.5)] hover:-translate-y-1 animate-slide-up animate-delay-300"
        >
            <Terminal className="w-5 h-5"/>
            <span>Initialize Lab Environment</span>
            <span className="absolute right-3 opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition-all duration-300">→</span>
        </button>
      </div>

      {/* Feature Grid */}
      <div className="max-w-6xl mx-auto grid md:grid-cols-3 gap-6 mb-16">
        <div className="bg-cyber-800/50 p-6 rounded-xl border border-cyber-700 hover:border-cyber-accent/50 transition-colors group animate-slide-up animate-delay-100">
            <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <PlayCircle className="w-6 h-6 text-purple-400"/>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Attack Simulations</h3>
            <p className="text-slate-400 text-sm">
                Don't just read about vulnerabilities—exploit them. Safely execute SQL injections, bypass access controls, and crack weak crypto in our sandboxed terminals.
            </p>
        </div>

        <div className="bg-cyber-800/50 p-6 rounded-xl border border-cyber-700 hover:border-cyber-accent/50 transition-colors group animate-slide-up animate-delay-200">
            <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <GitBranch className="w-6 h-6 text-blue-400"/>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">DevOps Integration</h3>
            <p className="text-slate-400 text-sm">
                Shift left. Visualize how modern CI/CD tools like SonarQube, Snyk, and ZAP detect vulnerabilities before they reach production.
            </p>
        </div>

        <div className="bg-cyber-800/50 p-6 rounded-xl border border-cyber-700 hover:border-cyber-accent/50 transition-colors group animate-slide-up animate-delay-300">
            <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Brain className="w-6 h-6 text-green-400"/>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">AI Remediation</h3>
            <p className="text-slate-400 text-sm">
                Stuck on a patch? Utilize the integrated Gemini AI consultant to generate secure code snippets and explain complex architectural fixes.
            </p>
        </div>
      </div>

      {/* How It Works */}
      <div className="max-w-5xl mx-auto bg-cyber-900 border border-cyber-700 rounded-2xl p-8 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-accent/5 blur-[100px] pointer-events-none"></div>
        
        <h2 className="text-2xl font-bold text-white mb-8 flex items-center gap-2">
            <Terminal className="text-cyber-accent"/> Lab Protocol
        </h2>

        <div className="grid md:grid-cols-4 gap-4">
             {[
                 { step: "01", title: "Select Target", desc: "Choose a vulnerability from the sidebar.", icon: MousePointer2 },
                 { step: "02", title: "Simulate", desc: "Run the attack in the Live Environment.", icon: Zap },
                 { step: "03", title: "Remediate", desc: "Use the Code Patcher to apply fixes.", icon: Lock },
                 { step: "04", title: "Verify", desc: "Run the CI/CD pipeline to pass the audit.", icon: Award },
             ].map((item, idx) => (
                 <div key={idx} className="relative p-4 rounded-lg bg-cyber-800/30 border border-cyber-700/50 hover:bg-cyber-800/80 transition-all">
                     <span className="text-5xl font-bold text-cyber-700 absolute top-2 right-2 opacity-20">{item.step}</span>
                     <item.icon className="w-6 h-6 text-cyber-accent mb-3"/>
                     <h4 className="font-bold text-white mb-1">{item.title}</h4>
                     <p className="text-xs text-slate-400">{item.desc}</p>
                 </div>
             ))}
        </div>
      </div>

      <div className="mt-16 text-center border-t border-cyber-800 pt-8">
        <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Powered By</p>
        <div className="flex justify-center gap-6 opacity-50 grayscale hover:grayscale-0 transition-all">
             <span className="font-bold text-slate-300 flex items-center gap-2"><Shield className="w-4 h-4"/> OWASP</span>
             <span className="font-bold text-slate-300 flex items-center gap-2"><Brain className="w-4 h-4"/> Google Gemini</span>
             <span className="font-bold text-slate-300 flex items-center gap-2"><Zap className="w-4 h-4"/> React 18</span>
        </div>
      </div>
    </div>
  );
};

export default Introduction;