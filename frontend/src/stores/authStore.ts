// ── SentinelClaw Auth Store (Zustand) ───────────────────────────────

import { create } from 'zustand';

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: string;
}

interface AuthState {
  token: string | null;
  user: User | null;
  isAuthenticated: boolean;
  mustChangePassword: boolean;
  login: (token: string, user: User, mustChangePassword?: boolean) => void;
  clearMustChangePassword: () => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('sc_token'),
  user: JSON.parse(localStorage.getItem('sc_user') || 'null'),
  isAuthenticated: !!localStorage.getItem('sc_token'),
  mustChangePassword: localStorage.getItem('sc_must_change') === 'true',

  login: (token, user, mustChangePassword = false) => {
    localStorage.setItem('sc_token', token);
    localStorage.setItem('sc_user', JSON.stringify(user));
    if (mustChangePassword) {
      localStorage.setItem('sc_must_change', 'true');
    } else {
      localStorage.removeItem('sc_must_change');
    }
    set({ token, user, isAuthenticated: true, mustChangePassword });
  },

  clearMustChangePassword: () => {
    localStorage.removeItem('sc_must_change');
    set({ mustChangePassword: false });
  },

  logout: () => {
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
    localStorage.removeItem('sc_must_change');
    set({ token: null, user: null, isAuthenticated: false, mustChangePassword: false });
  },
}));
