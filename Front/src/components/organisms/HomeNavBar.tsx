// src/components/organisms/HomeNavBar.tsx

import React from 'react';
import NavList from '../molecules/NavList';
import { navItems } from '../../constants/homeNavItems';
import './HomeNavBar.css';

const HomeNavBar: React.FC = () => (
  <div
    className="navbar bg-dark fixed-bottom d-flex"
    style={{
      height: 'var(--navbar-height)',
      justifyContent: 'space-around',
      alignItems: 'center',
    }}
  >
    <NavList items={navItems} />
  </div>
);

export default HomeNavBar;
