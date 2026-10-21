import React, { createContext, useContext, useState, useEffect } from 'react';
import type { User } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  login: (email: string, password?: string) => Promise<void>;
  loginAsDemo: (email: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('cybershield_user');
    if (!saved) return null;
    try {
      return JSON.parse(saved) as User;
    } catch {
      localStorage.removeItem('cybershield_user');
      return null;
    }
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('cybershield_token');
  });
  const [isLoading, setIsLoading] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    // Enforce dark mode by default
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const login = async (email: string, password = 'Nexora@2026') => {
    setIsLoading(true);
    try {
      const res = await api.login(email, password);
      const accessToken = res.data.access_token;
      const userData = res.data.user;

      setToken(accessToken);
      setUser(userData);
      localStorage.setItem('cybershield_token', accessToken);
      localStorage.setItem('cybershield_user', JSON.stringify(userData));
    } finally {
      setIsLoading(false);
    }
  };

  const loginAsDemo = async (email: string) => {
    return login(email, 'Nexora@2026');
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('cybershield_token');
    localStorage.removeItem('cybershield_user');
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        theme,
        toggleTheme,
        login,
        loginAsDemo,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
