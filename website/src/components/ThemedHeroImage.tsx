'use client';

import Image from 'next/image';
import { useTheme } from './ThemeProvider';
import { prefixPath } from '@/lib/utils';

export default function ThemedHeroImage() {
  const { theme, mounted } = useTheme();
  const src = mounted && theme === 'scratchpad' ? '/hero-sketch.png' : '/hero.png';

  return (
    <div className="kest-glow" style={{ 
      position: 'relative', 
      borderRadius: 'var(--radius-xl)', 
      overflow: 'hidden',
      aspectRatio: '1/1',
      boxShadow: 'var(--shadow-l4)'
    }}>
      <Image 
        src={prefixPath(src)} 
        alt="Kest — cryptographic lineage visualization" 
        fill 
        style={{ objectFit: 'cover' }}
        priority
      />
    </div>
  );
}
