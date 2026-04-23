import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import './index.css'
import App from './App.tsx'
import { WAFProvider } from './store/wafStore'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <WAFProvider>
        <App />
      </WAFProvider>
    </BrowserRouter>
  </StrictMode>,
)
