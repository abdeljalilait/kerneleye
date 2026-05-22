// SPDX-License-Identifier: AGPL-3.0-only

import { StrictMode } from 'react'
import { createRoot, hydrateRoot } from 'react-dom/client'
import { HelmetProvider } from 'react-helmet-async'
import './index.css'
import App from './App'

// Check if we're in SSR mode
const rootElement = document.getElementById('root')!

const AppWrapper = (
  <StrictMode>
    <HelmetProvider>
      <App />
    </HelmetProvider>
  </StrictMode>
)

// Use hydrate if server-rendered, otherwise createRoot
if (rootElement.hasChildNodes()) {
  hydrateRoot(rootElement, AppWrapper)
} else {
  createRoot(rootElement).render(AppWrapper)
}
