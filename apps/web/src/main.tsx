import React from 'react';
import ReactDOM from 'react-dom/client';
import '@xyflow/react/dist/style.css';
import './styles.css';
import { App } from './App';
import { ToastProvider } from './lib/Toast';
import { ConfirmProvider } from './lib/Confirm';
import { NavProvider } from './lib/nav';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ToastProvider>
      <ConfirmProvider>
        <NavProvider>
          <App />
        </NavProvider>
      </ConfirmProvider>
    </ToastProvider>
  </React.StrictMode>,
);
