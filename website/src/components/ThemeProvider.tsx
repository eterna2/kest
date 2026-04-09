'use client';

import { createContext, useContext, useState, useEffect } from 'react';

type Theme = 'obsidian' | 'scratchpad';

const ThemeContext = createContext<{
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
  mounted: boolean;
}>({ 
  theme: 'obsidian', 
  setTheme: () => {}, 
  toggleTheme: () => {},
  mounted: false 
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>('obsidian');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // Check local storage or system preference
    const stored = localStorage.getItem('kest-theme') as Theme | null;
    if (stored) {
      setThemeState(stored);
    } else {
      const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      setThemeState(prefersLight ? 'scratchpad' : 'obsidian');
    }
    setMounted(true);
  }, []);

  const setTheme = (t: Theme) => {
    setThemeState(t);
    localStorage.setItem('kest-theme', t);
    document.documentElement.setAttribute('data-theme', t);
  };

  const toggleTheme = () => setTheme(theme === 'obsidian' ? 'scratchpad' : 'obsidian');

  useEffect(() => {
    if (mounted) {
      document.documentElement.setAttribute('data-theme', theme);
    }
  }, [theme, mounted]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme, mounted }}>
      <div className={mounted ? 'theme-mounted' : ''}>
        {children}
      </div>
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
