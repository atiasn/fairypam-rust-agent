import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import App from './App';
import './styles/app.css';

const root = document.getElementById('root');
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 0, staleTime: 5_000 },
  },
});

if (!root) {
  throw new Error('Missing #root element');
}

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
