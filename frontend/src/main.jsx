import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import WelcomePage from './WelcomePage'
import BlockedPage from './BlockedPage'
import NormalRequestPage from './NormalRequestPage'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/blocked" element={<BlockedPage />} />
        <Route path="/normal" element={<NormalRequestPage />} />
        <Route path="*" element={<NormalRequestPage />} /> {/* fallback pour les routes inconnues */}
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
)
