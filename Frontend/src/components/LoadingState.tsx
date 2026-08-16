interface LoadingStateProps {
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading...'
}) => {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 12,
      padding: '48px 24px',
      color: 'var(--fg-muted)',
    }}>
      <div className="spinner" />
      <p style={{ fontSize: 13, color: 'var(--fg-muted)' }}>{message}</p>
    </div>
  );
};
