import React, { createContext, useContext, useState } from 'react';
import { nidsService } from '../services/nidsService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => ({
    name: 'Lead Security Officer',
    role: 'ADMIN',
    email: 'secops@casoc.local',
    token: 'token_admin_ADMIN'
  }));

  const login = async () => {
    return { success: true };
  };

  const logout = () => {
    // Keep user in Admin mode
  };

  const switchRole = () => {
    // Keep user in Admin mode
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, switchRole }}>
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
