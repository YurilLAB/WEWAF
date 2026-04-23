import { Component, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  errorMsg: string;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, errorMsg: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, errorMsg: error.message || 'Unknown error' };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('WEWAF Error Boundary caught:', error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  handleReset = () => {
    this.setState({ hasError: false, errorMsg: '' });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-waf-bg flex items-center justify-center p-4">
          <div className="bg-waf-panel border border-waf-border rounded-xl p-6 max-w-md w-full">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <h2 className="text-waf-text font-semibold">Something went wrong</h2>
                <p className="text-waf-dim text-xs">WEWAF encountered an error</p>
              </div>
            </div>

            <div className="bg-waf-elevated rounded-lg p-3 mb-4 border border-waf-border overflow-x-auto">
              <code className="text-xs text-red-400 font-mono block whitespace-pre-wrap">
                {this.state.errorMsg}
              </code>
            </div>

            <div className="flex gap-3">
              <button
                onClick={this.handleReload}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors"
              >
                <RefreshCw className="w-4 h-4" /> Reload Page
              </button>
              <button
                onClick={this.handleReset}
                className="flex-1 py-2.5 bg-waf-elevated text-waf-muted rounded-lg text-sm hover:bg-waf-border transition-colors"
              >
                Try Again
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
