import { Component, type ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  name: string;
}

interface State {
  hasError: boolean;
  errorMsg: string;
}

export default class PageErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, errorMsg: '' };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, errorMsg: error.message || 'Unknown error' };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error(`WEWAF Error in ${this.props.name}:`, error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, errorMsg: '' });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-waf-panel border border-waf-border rounded-xl p-6 m-4">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <h2 className="text-waf-text font-semibold text-sm">{this.props.name} Error</h2>
              <p className="text-waf-dim text-xs">This section encountered an error</p>
            </div>
          </div>

          <div className="bg-waf-elevated rounded-lg p-3 mb-4 border border-waf-border overflow-x-auto">
            <code className="text-xs text-red-400 font-mono block whitespace-pre-wrap">
              {this.state.errorMsg}
            </code>
          </div>

          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-4 py-2 bg-waf-orange text-white rounded-lg text-sm font-medium hover:bg-orange-600 transition-colors"
          >
            <RotateCcw className="w-4 h-4" /> Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
