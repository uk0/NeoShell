import { useEffect } from 'react';
import { useConnectionStore } from './stores/connectionStore';
import MasterPasswordSetup from './components/MasterPasswordSetup';
import UnlockScreen from './components/UnlockScreen';
import MainLayout from './components/MainLayout';

function LoadingScreen() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        background: 'var(--bg-primary)',
        color: 'var(--text-secondary)',
        fontSize: '16px',
      }}
    >
      Loading...
    </div>
  );
}

function App() {
  const { isPasswordSet, isVaultLocked, checkVaultStatus, loading } = useConnectionStore();

  useEffect(() => {
    checkVaultStatus();
  }, [checkVaultStatus]);

  if (loading) return <LoadingScreen />;
  if (!isPasswordSet) return <MasterPasswordSetup />;
  if (isVaultLocked) return <UnlockScreen />;
  return <MainLayout />;
}

export default App;
