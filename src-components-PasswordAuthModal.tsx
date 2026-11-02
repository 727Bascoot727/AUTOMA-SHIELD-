import React, { useState } from 'react';

interface PasswordAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const PasswordAuthModal: React.FC<PasswordAuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [attempts, setAttempts] = useState(3);

  if (!isOpen) return null;

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault();
    if (password === 'automa@123') {
      setPassword('');
      setErrorMsg('');
      onSuccess();
    } else {
      const nextAttempts = attempts - 1;
      setAttempts(nextAttempts);
      if (nextAttempts <= 0) {
        setErrorMsg('Access denied. Maximum verification attempts exceeded.');
      } else {
        setErrorMsg(`Invalid master credentials. ${nextAttempts} attempt(s) remaining.`);
      }
      setPassword('');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            🔒
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">Administrative Authorization Required</h3>
            <p className="text-xs text-slate-400">Enter master password to access protected security controls.</p>
          </div>
        </div>

        <form onSubmit={handleVerify} className="space-y-4">
          <div>
            <input
              type="password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter master password"
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-slate-100 text-sm focus:outline-none focus:border-sky-500"
            />
          </div>

          {errorMsg && (
            <div className="text-xs font-semibold text-rose-400 bg-rose-950/50 border border-rose-800/50 rounded-lg p-2.5">
              {errorMsg}
            </div>
          )}

          <div className="flex items-center justify-end space-x-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white shadow-lg shadow-sky-600/20 transition"
            >
              Verify & Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};