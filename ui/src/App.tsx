import { Routes, Route } from 'react-router';
import Dashboard from './pages/Dashboard';
import ErrorBoundary from './components/ErrorBoundary';

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </ErrorBoundary>
  );
}
