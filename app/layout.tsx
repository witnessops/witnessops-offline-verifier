import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'WitnessOps Offline Verifier',
  description: 'Local proof-bundle verifier with /verify dispositions.'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
