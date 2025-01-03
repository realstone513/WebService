// src/App.tsx

import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import AuthProvider from './contexts/AuthProvider';
import { AdminProvider } from './contexts/AdminContext';

import HomePage from './pages/HomePage';
import RegisterPage from './pages/RegisterPage';
import LoginPage from './pages/LoginPage';

import MyIngredientsPage from './pages/MyIngredientsPage';
import ChatBotPage from './pages/ChatBotPage';
import SettingsPage from './pages/SettingsPage';

import AdminPage from './pages/AdminPage';
import IngredientsManagement from './pages/ItemManagement';
import UserManagement from './pages/UserManagement';
import CategoryManagement from './pages/CategoryManagement';
import StorageMethodManagement from './pages/StorageMethodManagement';

const App: React.FC = () => {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/login" element={<LoginPage />} />

          <Route path="/my-ingredients" element={<MyIngredientsPage />} />
          <Route path="/chatbot" element={<ChatBotPage />} />
          <Route path="/settings" element={<SettingsPage />} />

          {/* 관리자 페이지 */}
          <Route
            path="/admin/*"
            element={
              <AdminProvider>
                <Routes>
                  <Route path="" element={<AdminPage />} />
                  <Route path="ingredients" element={<IngredientsManagement />} />
                  <Route path="users" element={<UserManagement />} />
                  <Route path="categories" element={<CategoryManagement />} />
                  <Route path="storage-methods" element={<StorageMethodManagement />} />
                </Routes>
              </AdminProvider>
            }
          />
        </Routes>
      </AuthProvider>
    </Router>
  );
};

export default App;
